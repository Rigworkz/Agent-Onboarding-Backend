param(
    [string]$Payload,
    [string]$BackendUrl = "http://35.224.207.37:5000",
    [string]$AgentUrl = "http://35.224.207.37:5000/scripts/agent.js",
    [string]$MockTelemetryUrl = "http://35.224.207.37:5000/scripts/mock-telemetry.json",
    [string]$InstallDir = "C:\rigworkz-agent",
    [string]$MinerUser = "root",
    [string]$MinerPass = "root",
    [int]$PingTimeoutMs = 500,
    [int]$EndpointTimeoutSec = 10,
    [int[]]$MinerPorts = @(80, 8080, 4028, 8888)
)

if (-not $Payload) {
    Write-Host "No payload provided"
    exit 1
}

function Write-Log {
    param([string]$Level, [string]$Message)
    $ts = (Get-Date).ToString("HH:mm:ss")
    $color = switch ($Level) {
        "INFO" { "Cyan" }
        "WARN" { "Yellow" }
        "OK"   { "Green" }
        "ERR"  { "Red" }
        default { "White" }
    }
    Write-Host ("[{0}]  {1}" -f $ts, $Message) -ForegroundColor $color
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

function Save-DiscoveryResult {
    param(
        [string]$InstallDir,
        [string]$Payload,
        [string]$BackendUrl,
        [string]$MachineId,
        [object]$Miner,
        [object]$Meta
    )

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        machine_id = $MachineId
        miner_ip   = if ($Miner) { $Miner.miner_ip } else { $null }
        miner_port = if ($Miner) { $Miner.miner_port } else { $null }
        discovery  = @{
            method        = "local-first + subnet-scan"
            status        = if ($Miner) { "found" } else { "not_found" }
            scanned_at    = (Get-Date).ToString("o")
            miner_type    = if ($Miner) { $Miner.miner_type } else { $null }
            auth_mode     = if ($Miner) { $Miner.auth_mode } else { $null }
            adapter       = $Meta.adapter
            subnet        = $Meta.subnet
            total_hosts   = $Meta.total_hosts
            checked_hosts = $Meta.checked_hosts
            alive_hosts   = $Meta.alive_hosts
        }
    } | ConvertTo-Json -Depth 5

    Set-Content -Path (Join-Path $InstallDir "config.json") -Value $config -Encoding Ascii
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

$ProbeScript = {
    param(
        [string]$Ip,
        [int]$Port,
        [int]$EndpointTimeoutSec,
        [string]$MinerUser,
        [string]$MinerPass
    )

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

    $uriPath = "/cgi-bin/stats.cgi"
    $url = "http://$Ip`:$Port$uriPath"

    try {
        $res = Invoke-WebRequest -Uri $url -TimeoutSec $EndpointTimeoutSec -UseBasicParsing -ErrorAction Stop
        if ($res.StatusCode -eq 200) {
            try {
                $json = $res.Content | ConvertFrom-Json -ErrorAction Stop
                if ($json -and $json.STATS -and @($json.STATS).Count -gt 0) {
                    $minerType = if ($json.INFO -and $json.INFO.type) { $json.INFO.type } elseif ($json.INFO -and $json.INFO.Type) { $json.INFO.Type } else { "unknown" }
                    return [pscustomobject]@{
                        miner_ip   = $Ip
                        miner_port = $Port
                        miner_type = $minerType
                        auth_mode  = "open"
                    }
                }
            }
            catch {
            }
        }
    }
    catch {
        $resp = $_.Exception.Response
        if ($resp -and [int]$resp.StatusCode -eq 401) {
            $header = $resp.Headers["WWW-Authenticate"]
            if ($header) {
                try {
                    $ch = Parse-AuthChallenge -Header $header
                    $authHdr = Build-DigestAuthHeader -Method "GET" -UriPath $uriPath -Challenge $ch -User $MinerUser -Pass $MinerPass

                    $authed = Invoke-WebRequest -Uri $url -Headers @{ Authorization = $authHdr } -TimeoutSec $EndpointTimeoutSec -UseBasicParsing -ErrorAction Stop
                    if ($authed.StatusCode -eq 200) {
                        $json = $authed.Content | ConvertFrom-Json -ErrorAction Stop
                        if ($json -and $json.STATS -and @($json.STATS).Count -gt 0) {
                            $minerType = if ($json.INFO -and $json.INFO.type) { $json.INFO.type } elseif ($json.INFO -and $json.INFO.Type) { $json.INFO.Type } else { "unknown" }
                            return [pscustomobject]@{
                                miner_ip   = $Ip
                                miner_port = $Port
                                miner_type = $minerType
                                auth_mode  = "digest"
                            }
                        }
                    }
                }
                catch {
                }
            }
        }
    }

    return $null
}

function Get-OrderedPorts {
    param(
        [int]$PreferredPort = 0,
        [int[]]$Ports
    )

    $ordered = New-Object System.Collections.Generic.List[int]

    if ($PreferredPort -gt 0) {
        [void]$ordered.Add($PreferredPort)
    }

    foreach ($p in $Ports) {
        if ($p -gt 0 -and -not $ordered.Contains($p)) {
            [void]$ordered.Add($p)
        }
    }

    return ,$ordered.ToArray()
}

function Test-MinerEndpoint {
    param(
        [string]$Ip,
        [int]$PreferredPort = 0
    )

    $ports = Get-OrderedPorts -PreferredPort $PreferredPort -Ports $MinerPorts

    $jobs = @()
    foreach ($port in $ports) {
        $jobs += Start-Job -ScriptBlock $ProbeScript -ArgumentList $Ip, $port, $EndpointTimeoutSec, $MinerUser, $MinerPass
    }

    try {
        while ($jobs.Count -gt 0) {
            $completedJobs = @(Wait-Job -Job $jobs -Any)

            foreach ($completedJob in $completedJobs) {
                $result = $null
                try {
                    $result = Receive-Job -Job $completedJob -ErrorAction SilentlyContinue
                }
                catch {
                }

                Remove-Job -Job $completedJob -Force -ErrorAction SilentlyContinue
                $jobs = @($jobs | Where-Object { $_.Id -ne $completedJob.Id })

                if ($result) {
                    foreach ($otherJob in $jobs) {
                        Stop-Job -Job $otherJob -ErrorAction SilentlyContinue
                        Remove-Job -Job $otherJob -Force -ErrorAction SilentlyContinue
                    }
                    return $result
                }
            }
        }
    }
    finally {
        foreach ($job in $jobs) {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }

    return $null
}

# Pings all hosts simultaneously using async .NET API.
# Returns a list of IPs that responded, sorted by how fast they replied.
function Get-AliveHosts {
    param(
        [string[]]$Hosts,
        [int]$TimeoutMs
    )

    $entries = [System.Collections.Generic.List[object]]::new()

    foreach ($h in $Hosts) {
        $p = [System.Net.NetworkInformation.Ping]::new()
        $entries.Add([pscustomobject]@{
            Ip   = $h
            Ping = $p
            Task = $p.SendPingAsync($h, $TimeoutMs)
        })
    }

    try {
        [System.Threading.Tasks.Task]::WaitAll(($entries | ForEach-Object { $_.Task }))
    }
    catch {
        # WaitAll throws AggregateException if any task faulted -- that is fine,
        # we check individual results below.
    }

    $alive = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $entries) {
        try {
            if ($e.Task.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and
                $e.Task.Result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                [void]$alive.Add($e.Ip)
            }
        }
        catch { }
        finally {
            try { $e.Ping.Dispose() } catch { }
        }
    }

    return $alive
}

function Discover-Miner {
    param([string]$InstallDir)

    $cfg = Get-PrimaryIPv4Config
    $ip = $cfg.IPv4Address.IPAddress
    $prefix = $cfg.IPv4Address.PrefixLength
    $gateway = $cfg.IPv4DefaultGateway.NextHop

    Write-Log "INFO" "Adapter    : $($cfg.InterfaceAlias)"
    Write-Log "INFO" "Local IP   : $ip"
    Write-Log "INFO" "Subnet     : $ip/$prefix"
    Write-Host ""

    $meta = @{
        adapter       = $cfg.InterfaceAlias
        subnet        = "$ip/$prefix"
        total_hosts   = 0
        checked_hosts = 0
        alive_hosts   = 0
    }

    # --- Check cache first ---
    $cached = Get-CachedDiscovery -InstallDir $InstallDir
    if ($cached -and $cached.miner_ip) {
        Write-Log "INFO" "Trying last known miner at $($cached.miner_ip):$($cached.miner_port) ..."
        $cachedMiner = Test-MinerEndpoint -Ip $cached.miner_ip -PreferredPort ([int]($cached.miner_port))
        if ($cachedMiner) {
            Write-Log "OK"   "Miner still reachable - skipping scan"
            return [pscustomobject]@{ Miner = $cachedMiner; Meta = $meta }
        }
        Write-Log "WARN" "Cached miner not responding, moving on"
    }

    # --- Try local IP before scanning ---
    Write-Log "INFO" "Checking local machine (ports $($MinerPorts -join ' / ')) ..."
    $localMiner = Test-MinerEndpoint -Ip $ip -PreferredPort 8080
    if ($localMiner) {
        Write-Log "OK" "Miner found on local machine - $($localMiner.miner_ip):$($localMiner.miner_port)"
        return [pscustomobject]@{ Miner = $localMiner; Meta = $meta }
    }

    # --- Parallel ping sweep ---
    $allHosts = @(Get-SubnetHosts -Ip $ip -PrefixLength $prefix | Where-Object { $_ -ne $ip -and $_ -ne $gateway })
    $meta.total_hosts = $allHosts.Count

    Write-Host ""
    Write-Log "INFO" "Pinging $($allHosts.Count) hosts in parallel ..."

    $aliveHosts = Get-AliveHosts -Hosts $allHosts -TimeoutMs $PingTimeoutMs

    $meta.alive_hosts = $aliveHosts.Count
    Write-Log "INFO" "$($aliveHosts.Count) host(s) responded - probing for miner ..."

    # --- Probe each alive host ---
    $checked = 0
    foreach ($candidate in $aliveHosts) {
        $checked++
        $miner = Test-MinerEndpoint -Ip $candidate
        if ($miner) {
            $meta.checked_hosts = $checked
            return [pscustomobject]@{ Miner = $miner; Meta = $meta }
        }
    }

    $meta.checked_hosts = $checked
    return [pscustomobject]@{ Miner = $null; Meta = $meta }
}

try {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $machineId = [guid]::NewGuid().ToString()

    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor DarkCyan
    Write-Host "   RigWorkz Agent Installer" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor DarkCyan
    Write-Host ""

    Write-Log "INFO" "Starting miner discovery ..."
    Write-Host ""

    $result = Discover-Miner -InstallDir $InstallDir
    $miner = $result.Miner

    Write-Host ""

    if ($miner) {
        Write-Log "OK"   "Miner found - $($miner.miner_ip):$($miner.miner_port) ($($miner.miner_type), auth: $($miner.auth_mode))"
    }
    else {
        Write-Log "WARN" "No miner found on this network (scanned $($result.Meta.checked_hosts) hosts, $($result.Meta.alive_hosts) alive)"
    }

    Write-Host ""
    Write-Log "INFO" "Saving config ..."
    Save-DiscoveryResult `
        -InstallDir $InstallDir `
        -Payload $Payload `
        -BackendUrl $BackendUrl `
        -MachineId $machineId `
        -Miner $miner `
        -Meta $result.Meta

    Write-Log "INFO" "Downloading agent ..."
    $agentDest = Join-Path $InstallDir "agent.js"
    Invoke-WebRequest -Uri $AgentUrl -OutFile $agentDest

    $mockDest = Join-Path $InstallDir "mock-telemetry.json"
    Invoke-WebRequest -Uri $MockTelemetryUrl -OutFile $mockDest

    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Write-Host ""
        Write-Log "ERR" "Node.js is not installed or not in PATH - cannot start agent"
        exit 1
    }

    Write-Log "INFO" "Launching agent process ..."
    Start-Process -FilePath "node" -ArgumentList "`"$agentDest`"" -WorkingDirectory $InstallDir -NoNewWindow

    Write-Host ""
    Write-Log "OK"  "Agent is running. All done."
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Log "ERR" "Installation failed: $($_.Exception.Message)"
    exit 1
}