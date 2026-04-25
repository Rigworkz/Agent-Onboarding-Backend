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
    [int]$PingThrottle = 64
)

if (-not $Payload) {
    Write-Host "No payload provided"
    exit 1
}

function Write-Log {
    param([string]$Level, [string]$Message)
    Write-Host ("[{0}] [{1}] {2}" -f (Get-Date).ToString("o"), $Level, $Message)
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

function Get-CachedDiscovery {
    param([string]$InstallDir)

    $configPath = Join-Path $InstallDir "config.json"
    if (-not (Test-Path $configPath)) {
        return $null
    }

    try {
        return (Get-Content $configPath -Raw | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Invoke-ParallelPingScan {
    param(
        [string[]]$Ips,
        [int]$TimeoutMs = 250,
        [int]$Throttle = 64
    )

    $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
    $pool.Open()

    $pending = New-Object System.Collections.ArrayList
    $alive = New-Object System.Collections.Generic.List[string]
    $submitted = 0
    $checked = 0
    $nextLog = 100

    try {
        while ($submitted -lt $Ips.Count -or $pending.Count -gt 0) {
            while ($submitted -lt $Ips.Count -and $pending.Count -lt $Throttle) {
                $ip = $Ips[$submitted]
                $submitted++

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
finally {
    $ping.Dispose()
}
'@).AddArgument($ip).AddArgument($TimeoutMs)

                $handle = $ps.BeginInvoke()
                [void]$pending.Add([pscustomobject]@{
                    PS = $ps
                    Handle = $handle
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
                    if ($checked -ge $nextLog -or ($submitted -eq $Ips.Count -and $pending.Count -eq 0)) {
                        Write-Log "INFO" "Ping progress: checked=$checked alive=$($alive.Count)"
                        $nextLog += 100
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
    foreach ($m in [regex]::Matches($Header, '(\w+)=(?:"([^"]+)"|([^\s,]+))')) {
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

        return ('Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", qop=auth, nc={4}, cnonce="{5}", response="{6}"' -f `
            $User, $realm, $nonce, $UriPath, $nc, $cnonce, $response)
    }

    $response = Get-Md5Hex "$ha1`:$nonce`:$ha2"
    return ('Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", response="{4}"' -f `
        $User, $realm, $nonce, $UriPath, $response)
}

function Test-MinerEndpoint {
    param(
        [string]$Ip,
        [int]$PreferredPort = 0
    )

    $uriPath = "/cgi-bin/stats.cgi"

    $ports = @()
    if ($PreferredPort -gt 0) { $ports += $PreferredPort }
    $ports += 8080
    $ports += 80
    $ports = $ports | Select-Object -Unique

    foreach ($port in $ports) {
        $url = "http://$Ip`:$port$uriPath"

        try {
            $json = Invoke-RestMethod -Uri $url -TimeoutSec $EndpointTimeoutSec -Method Get -ErrorAction Stop

            if ($json -and $json.INFO -and $json.INFO.type -and $json.STATS -and $json.STATS.Count -gt 0) {
                return [pscustomobject]@{
                    miner_ip   = $Ip
                    miner_port = $port
                    miner_type = $json.INFO.type
                    auth_mode  = "open"
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

                        $json = Invoke-RestMethod -Uri $url -Headers @{ Authorization = $authHeader } -TimeoutSec $EndpointTimeoutSec -Method Get -ErrorAction Stop

                        if ($json -and $json.INFO -and $json.INFO.type -and $json.STATS -and $json.STATS.Count -gt 0) {
                            return [pscustomobject]@{
                                miner_ip   = $Ip
                                miner_port = $port
                                miner_type = $json.INFO.type
                                auth_mode  = "digest"
                            }
                        }
                    }
                    catch {
                    }
                }
            }
        }
    }

    return $null
}

function Discover-Miner {
    param([string]$InstallDir)

    $cfg = Get-PrimaryIPv4Config
    $ip = $cfg.IPv4Address.IPAddress
    $prefix = $cfg.IPv4Address.PrefixLength
    $gateway = $cfg.IPv4DefaultGateway.NextHop

    Write-Log "INFO" "Adapter: $($cfg.InterfaceAlias)"
    Write-Log "INFO" "Local IP: $ip"
    Write-Log "INFO" "Subnet: $ip/$prefix"

    $cached = Get-CachedDiscovery -InstallDir $InstallDir
    if ($cached -and $cached.miner_ip) {
        Write-Log "INFO" "Trying cached miner first: $($cached.miner_ip):$($cached.miner_port)"
        $cachedMiner = Test-MinerEndpoint -Ip $cached.miner_ip -PreferredPort ([int]($cached.miner_port))
        if ($cachedMiner) {
            Write-Log "INFO" "Miner found: $($cachedMiner.miner_ip):$($cachedMiner.miner_port) type=$($cachedMiner.miner_type) auth=$($cachedMiner.auth_mode)"
            return $cachedMiner
        }
    }

    Write-Log "INFO" "Trying local IP first: $ip"
    $localMiner = Test-MinerEndpoint -Ip $ip -PreferredPort 8080
    if ($localMiner) {
        Write-Log "INFO" "Miner found: $($localMiner.miner_ip):$($localMiner.miner_port) type=$($localMiner.miner_type) auth=$($localMiner.auth_mode)"
        return $localMiner
    }

    $hosts = Get-SubnetHosts -Ip $ip -PrefixLength $prefix
    $hosts = $hosts | Where-Object {
        $_ -ne $ip -and $_ -ne $gateway -and
        (-not $cached -or $_ -ne $cached.miner_ip)
    }

    Write-Log "INFO" "Total hosts: $($hosts.Count)"
    Write-Log "INFO" "Scan mode: parallel ping + immediate verify"

    $scan = Invoke-ParallelPingScan -Ips $hosts -TimeoutMs $PingTimeoutMs -Throttle $PingThrottle
    Write-Log "INFO" "Alive hosts: $($scan.AliveHosts.Count)"

    foreach ($candidate in $scan.AliveHosts) {
        Write-Log "INFO" "Verifying ${candidate}:80/8080"
        $miner = Test-MinerEndpoint -Ip $candidate
        if ($miner) {
            Write-Log "INFO" "Miner found: $($miner.miner_ip):$($miner.miner_port) type=$($miner.miner_type) auth=$($miner.auth_mode)"
            return $miner
        }

        Write-Log "WARN" "Candidate rejected: $candidate"
    }

    return $null
}

try {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $machineId = [guid]::NewGuid().ToString()

    Write-Log "INFO" "Starting network scan..."
    $miner = Discover-Miner -InstallDir $InstallDir

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        machine_id = $machineId
        miner_ip   = if ($miner) { $miner.miner_ip } else { $null }
        miner_port = if ($miner) { $miner.miner_port } else { $null }
        discovery  = @{
            method     = "parallel-ping+endpoint-verify"
            status     = if ($miner) { "found" } else { "not_found" }
            scanned_at = (Get-Date).ToString("o")
            miner_type = if ($miner) { $miner.miner_type } else { $null }
            auth_mode  = if ($miner) { $miner.auth_mode } else { $null }
        }
    } | ConvertTo-Json -Depth 5

    $configPath = Join-Path $InstallDir "config.json"
    Set-Content -Path $configPath -Value $config -Encoding Ascii

    $agentDest = Join-Path $InstallDir "agent.js"
    Invoke-WebRequest -Uri $AgentUrl -OutFile $agentDest

    $mockDest = Join-Path $InstallDir "mock-telemetry.json"
    Invoke-WebRequest -Uri $MockTelemetryUrl -OutFile $mockDest

    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Write-Host "Node.js is not installed or not available in PATH"
        exit 1
    }

    Write-Log "INFO" "Starting agent..."
    Start-Process -FilePath "node" -ArgumentList "`"$agentDest`"" -WorkingDirectory $InstallDir -NoNewWindow
}
catch {
    Write-Host "Installation failed: $($_.Exception.Message)"
    exit 1
}