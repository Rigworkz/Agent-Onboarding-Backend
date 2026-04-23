param(
    [string]$Payload,
    [string]$BackendUrl = "http://35.224.207.37:5000",
    [string]$AgentUrl = "http://35.224.207.37:5000/scripts/agent.js",
    [string]$MockTelemetryUrl = "http://35.224.207.37:5000/scripts/mock-telemetry.json",
    [string]$InstallDir = "C:\rigworkz-agent",
    [string]$MinerUser = "root",
    [string]$MinerPass = "root",
    [int]$PingTimeoutMs = 250,
    [int]$EndpointTimeoutSec = 1,
    [int]$ScanThrottle = 64,
    [int]$ProgressIntervalSec = 5
)

if (-not $Payload) {
    Write-Host "No payload provided"
    exit 1
}

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date).ToString("o"), $Level, $Message
    Write-Host $line
}

function Get-PrimaryIPv4Config {
    $cfg = Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4Address -and
            $_.IPv4DefaultGateway -and
            $_.NetAdapter.Status -eq "Up" -and
            $_.InterfaceAlias -notmatch "Tailscale|Loopback"
        } |
        Select-Object -First 1

    if (-not $cfg) {
        throw "No active IPv4 adapter found"
    }

    return $cfg
}

function Get-MaskBytesFromPrefixLength {
    param([int]$PrefixLength)

    $mask = New-Object byte[] 4
    for ($i = 0; $i -lt 4; $i++) {
        $bits = $PrefixLength - ($i * 8)

        if ($bits -ge 8) {
            $mask[$i] = 255
        }
        elseif ($bits -le 0) {
            $mask[$i] = 0
        }
        else {
            $mask[$i] = [byte](256 - [int][math]::Pow(2, 8 - $bits))
        }
    }

    return $mask
}

function Convert-BytesToUInt32 {
    param([byte[]]$Bytes)

    $tmp = $Bytes.Clone()
    [Array]::Reverse($tmp)
    return [BitConverter]::ToUInt32($tmp, 0)
}

function Convert-UInt32ToIp {
    param([uint32]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-SubnetHosts {
    param(
        [string]$Ip,
        [int]$PrefixLength
    )

    $ipBytes = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    $maskBytes = Get-MaskBytesFromPrefixLength -PrefixLength $PrefixLength

    $networkBytes = New-Object byte[] 4
    $wildcardBytes = New-Object byte[] 4

    for ($i = 0; $i -lt 4; $i++) {
        $networkBytes[$i] = $ipBytes[$i] -band $maskBytes[$i]
        $wildcardBytes[$i] = 255 - $maskBytes[$i]
    }

    $networkInt = Convert-BytesToUInt32 -Bytes $networkBytes
    $wildcardInt = Convert-BytesToUInt32 -Bytes $wildcardBytes

    $start = [uint64]$networkInt + 1
    $end = [uint64]$networkInt + [uint64]$wildcardInt - 1

    $hosts = New-Object System.Collections.Generic.List[string]
    for ($n = $start; $n -le $end; $n++) {
        $hosts.Add((Convert-UInt32ToIp -Value ([uint32]$n)))
    }

    return $hosts
}

function Invoke-ParallelPingScan {
    param(
        [string[]]$Ips,
        [int]$Throttle = 64,
        [int]$TimeoutMs = 250,
        [int]$ProgressIntervalSec = 5
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
    $pool.Open()

    $queue = New-Object System.Collections.Generic.Queue[string]
    foreach ($ip in $Ips) {
        $queue.Enqueue($ip)
    }

    $pending = New-Object System.Collections.ArrayList
    $alive = New-Object System.Collections.Generic.List[string]
    $checked = 0
    $lastProgress = [datetime]::UtcNow

    try {
        while ($queue.Count -gt 0 -or $pending.Count -gt 0) {
            while ($queue.Count -gt 0 -and $pending.Count -lt $Throttle) {
                $ip = $queue.Dequeue()

                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddScript(@'
param($TargetIp, $TimeoutMs)

$ping = [System.Net.NetworkInformation.Ping]::new()
try {
    $reply = $ping.Send($TargetIp, $TimeoutMs)
    if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
        $TargetIp
    }
}
catch {
}
finally {
    $ping.Dispose()
}
'@).AddArgument($ip).AddArgument($TimeoutMs)

                $handle = $ps.BeginInvoke()
                [void]$pending.Add([pscustomobject]@{
                    PS = $ps
                    Handle = $handle
                    Ip = $ip
                })
            }

            for ($i = $pending.Count - 1; $i -ge 0; $i--) {
                $item = $pending[$i]
                if ($item.Handle.IsCompleted) {
                    try {
                        $result = @($item.PS.EndInvoke($item.Handle))
                        if ($result.Count -gt 0 -and $result[0]) {
                            [void]$alive.Add([string]$result[0])
                        }
                    }
                    catch {
                    }
                    finally {
                        $item.PS.Dispose()
                        [void]$pending.RemoveAt($i)
                    }

                    $checked++
                    if (
                        ([datetime]::UtcNow - $lastProgress).TotalSeconds -ge $ProgressIntervalSec -or
                        $checked -eq $Ips.Count
                    ) {
                        Write-Log "INFO" ("Ping progress: {0}/{1} checked, {2} alive, elapsed {3}" -f `
                            $checked, $Ips.Count, $alive.Count, $stopwatch.Elapsed.ToString("hh\:mm\:ss"))
                        $lastProgress = [datetime]::UtcNow
                    }
                }
            }

            Start-Sleep -Milliseconds 25
        }
    }
    finally {
        $pool.Close()
        $pool.Dispose()
    }

    return [pscustomobject]@{
        AliveHosts = $alive.ToArray()
        Checked    = $checked
        Total      = $Ips.Count
        ElapsedMs  = $stopwatch.ElapsedMilliseconds
    }
}

function Get-Md5Hex {
    param([string]$Text)

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $md5.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        $md5.Dispose()
    }
}

function Parse-AuthChallenge {
    param([string]$Header)

    $out = @{}
    $re = '(\w+)=(?:"([^"]+)"|([^\s,]+))'

    foreach ($m in [regex]::Matches($Header, $re)) {
        $out[$m.Groups[1].Value] = if ($m.Groups[2].Value) { $m.Groups[2].Value } else { $m.Groups[3].Value }
    }

    return $out
}

function Build-DigestAuthHeader {
    param(
        [string]$Method,
        [string]$UriPath,
        [hashtable]$Challenge,
        [string]$User,
        [string]$Pass
    )

    $realm = $Challenge.realm
    $nonce = $Challenge.nonce
    $qop = $Challenge.qop

    $ha1 = Get-Md5Hex "$User`:$realm`:$Pass"
    $ha2 = Get-Md5Hex "$Method`:$UriPath"

    if ($qop -and $qop -like "*auth*") {
        $nc = "00000001"
        $cnonce = ([guid]::NewGuid().ToString("N")).Substring(0, 16)
        $response = Get-Md5Hex "$ha1`:$nonce`:$nc`:$cnonce`:auth`:$ha2"

        return (
            'Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", qop=auth, nc={4}, cnonce="{5}", response="{6}"' -f `
            $User, $realm, $nonce, $UriPath, $nc, $cnonce, $response
        )
    }

    $response = Get-Md5Hex "$ha1`:$nonce`:$ha2"

    return (
        'Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", response="{4}"' -f `
        $User, $realm, $nonce, $UriPath, $response
    )
}

function Invoke-MinerStatsCheck {
    param(
        [string]$Ip,
        [int[]]$Ports = @(80, 8080)
    )

    $uriPath = "/cgi-bin/stats.cgi"

    foreach ($port in $Ports) {
        $url = "http://$Ip`:$port$uriPath"
        Write-Log "INFO" "Verifying candidate $Ip on port $port"

        try {
            $probe = Invoke-WebRequest -Uri $url -TimeoutSec $EndpointTimeoutSec -UseBasicParsing -ErrorAction Stop

            if ($probe.StatusCode -eq 200) {
                try {
                    $json = $probe.Content | ConvertFrom-Json
                    if ($json.INFO.type -and $json.STATS[0]) {
                        return [pscustomobject]@{
                            miner_ip   = $Ip
                            miner_port = $port
                            miner_type = $json.INFO.type
                            auth_mode  = "open"
                        }
                    }
                }
                catch {
                    Write-Log "WARN" "Candidate $Ip:$port returned 200 but response was not valid miner JSON"
                }
            }
        }
        catch {
            $resp = $_.Exception.Response

            if ($resp -and [int]$resp.StatusCode -eq 401) {
                $challengeHeader = $resp.Headers["WWW-Authenticate"]

                if ($challengeHeader) {
                    try {
                        $challenge = Parse-AuthChallenge -Header $challengeHeader
                        $authHeader = Build-DigestAuthHeader -Method "GET" -UriPath $uriPath -Challenge $challenge -User $MinerUser -Pass $MinerPass

                        $authed = Invoke-WebRequest -Uri $url -Headers @{ Authorization = $authHeader } -TimeoutSec $EndpointTimeoutSec -UseBasicParsing -ErrorAction Stop

                        if ($authed.StatusCode -eq 200) {
                            $json = $authed.Content | ConvertFrom-Json
                            if ($json.INFO.type -and $json.STATS[0]) {
                                return [pscustomobject]@{
                                    miner_ip   = $Ip
                                    miner_port = $port
                                    miner_type = $json.INFO.type
                                    auth_mode  = "digest"
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log "INFO" "Digest verification failed for $Ip:$port"
                    }
                }
            }
        }
    }

    return $null
}

function Discover-Miner {
    $cfg = Get-PrimaryIPv4Config
    $ip = $cfg.IPv4Address.IPAddress
    $prefix = $cfg.IPv4Address.PrefixLength
    $subnetLabel = "$ip/$prefix"

    Write-Log "INFO" "Adapter: $($cfg.InterfaceAlias)"
    Write-Log "INFO" "Local IP: $ip"
    Write-Log "INFO" "Subnet: $subnetLabel"

    $hosts = Get-SubnetHosts -Ip $ip -PrefixLength $prefix
    Write-Log "INFO" "Total hosts to scan: $($hosts.Count)"
    Write-Log "INFO" "Scan mode: parallel ping + endpoint verify"
    Write-Log "INFO" "Verifier ports: 80, 8080"

    $scan = Invoke-ParallelPingScan -Ips $hosts -Throttle $ScanThrottle -TimeoutMs $PingTimeoutMs -ProgressIntervalSec $ProgressIntervalSec

    Write-Log "INFO" "Ping scan complete: $($scan.Checked)/$($scan.Total) checked, $($scan.AliveHosts.Count) alive, elapsed $([TimeSpan]::FromMilliseconds($scan.ElapsedMs).ToString())"

    $verifiedCount = 0
    foreach ($candidate in $scan.AliveHosts) {
        $verifiedCount++
        $miner = Invoke-MinerStatsCheck -Ip $candidate -Ports @(80, 8080)

        if ($miner) {
            Write-Log "INFO" "Miner confirmed: $($miner.miner_ip):$($miner.miner_port) | type=$($miner.miner_type) | auth=$($miner.auth_mode)"

            return [pscustomobject]@{
                Found = $true
                Miner = $miner
                Scan = $scan
                VerifiedCount = $verifiedCount
                Subnet = $subnetLabel
                Adapter = $cfg.InterfaceAlias
            }
        }

        Write-Log "WARN" "Candidate rejected: $candidate"
    }

    Write-Log "WARN" "Discovery completed with no miner found"

    return [pscustomobject]@{
        Found = $false
        Miner = $null
        Scan = $scan
        VerifiedCount = $verifiedCount
        Subnet = $subnetLabel
        Adapter = $cfg.InterfaceAlias
    }
}

try {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $machineId = [guid]::NewGuid().ToString()

    Write-Log "INFO" "Starting network scan..."
    $discovery = Discover-Miner

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        machine_id = $machineId
        miner_ip   = if ($discovery.Found) { $discovery.Miner.miner_ip } else { $null }
        miner_port = if ($discovery.Found) { $discovery.Miner.miner_port } else { $null }
        discovery  = @{
            method            = "parallel-ping+http-digest"
            status            = if ($discovery.Found) { "found" } else { "not_found" }
            adapter           = $discovery.Adapter
            subnet            = $discovery.Subnet
            total_hosts       = $discovery.Scan.Total
            checked_hosts     = $discovery.Scan.Checked
            alive_hosts       = $discovery.Scan.AliveHosts.Count
            verified_candidates = $discovery.VerifiedCount
            elapsed_ms        = $discovery.Scan.ElapsedMs
            scanned_at        = (Get-Date).ToString("o")
            miner_type        = if ($discovery.Found) { $discovery.Miner.miner_type } else { $null }
            auth_mode         = if ($discovery.Found) { $discovery.Miner.auth_mode } else { $null }
        }
    } | ConvertTo-Json -Depth 6

    $configPath = Join-Path $InstallDir "config.json"
    Set-Content -Path $configPath -Value $config -Encoding Ascii

    $agentDest = Join-Path $InstallDir "agent.js"
    Write-Host "Downloading agent from $AgentUrl ..."
    Invoke-WebRequest -Uri $AgentUrl -OutFile $agentDest

    $mockDest = Join-Path $InstallDir "mock-telemetry.json"
    Write-Host "Downloading mock telemetry from $MockTelemetryUrl ..."
    Invoke-WebRequest -Uri $MockTelemetryUrl -OutFile $mockDest

    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if (-not $nodeCmd) {
        Write-Host "Node.js is not installed or not available in PATH"
        exit 1
    }

    Write-Host "Starting agent..."
    Start-Process -FilePath "node" -ArgumentList "`"$agentDest`"" -WorkingDirectory $InstallDir -NoNewWindow
}
catch {
    Write-Host "Installation failed: $($_.Exception.Message)"
    exit 1
}