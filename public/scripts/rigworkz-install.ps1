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

# ── Logger ───────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Level, [string]$Message)
    Write-Host ("[{0}] [{1}] {2}" -f (Get-Date).ToString("o"), $Level, $Message)
}

# ── Network helpers ──────────────────────────────────────────────────────────
function Get-PrimaryIPv4Config {
    $cfg = Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4Address -and
            $_.IPv4DefaultGateway -and
            $_.NetAdapter.Status -eq "Up" -and
            $_.InterfaceAlias -notmatch "Tailscale|Loopback"
        } |
        Select-Object -First 1
    if (-not $cfg) { throw "No active IPv4 adapter found" }
    return $cfg
}

function Get-SubnetHosts {
    param([string]$Ip, [int]$PrefixLength)

    $ipBytes   = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    $maskBytes = New-Object byte[] 4
    for ($i = 0; $i -lt 4; $i++) {
        $bits          = $PrefixLength - ($i * 8)
        $maskBytes[$i] = if ($bits -ge 8) { 255 } elseif ($bits -le 0) { 0 } else { [byte](256 - [int][math]::Pow(2, 8 - $bits)) }
    }

    $networkBytes  = New-Object byte[] 4
    $wildcardBytes = New-Object byte[] 4
    for ($i = 0; $i -lt 4; $i++) {
        $networkBytes[$i]  = $ipBytes[$i] -band $maskBytes[$i]
        $wildcardBytes[$i] = 255 - $maskBytes[$i]
    }

    $tmp = $networkBytes.Clone(); [Array]::Reverse($tmp);  $networkInt  = [BitConverter]::ToUInt32($tmp, 0)
    $tmp = $wildcardBytes.Clone(); [Array]::Reverse($tmp); $wildcardInt = [BitConverter]::ToUInt32($tmp, 0)

    $start = [uint64]$networkInt + 1
    $end   = [uint64]$networkInt + [uint64]$wildcardInt - 1

    $hosts = [System.Collections.Generic.List[string]]::new()
    for ($n = $start; $n -le $end; $n++) {
        $bytes = [BitConverter]::GetBytes([uint32]$n)
        [Array]::Reverse($bytes)
        $hosts.Add(([System.Net.IPAddress]::new($bytes)).ToString())
    }
    return $hosts
}

# ── Config helpers ───────────────────────────────────────────────────────────
function Get-CachedDiscovery {
    param([string]$InstallDir)
    $configPath = Join-Path $InstallDir "config.json"
    if (-not (Test-Path $configPath)) { return $null }
    try { return (Get-Content $configPath -Raw | ConvertFrom-Json) } catch { return $null }
}

function Save-DiscoveryResult {
    param(
        [string]$InstallDir,
        [string]$Payload,
        [string]$BackendUrl,
        [string]$MachineId,
        [object]$Miner,
        [object]$DiscoveryMeta
    )

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        machine_id = $MachineId
        miner_ip   = if ($Miner) { $Miner.miner_ip }   else { $null }
        miner_port = if ($Miner) { $Miner.miner_port } else { $null }
        discovery  = @{
            method      = "parallel-ping+endpoint-verify"
            status      = if ($Miner) { "found" } else { "not_found" }
            scanned_at  = (Get-Date).ToString("o")
            miner_type  = if ($Miner) { $Miner.miner_type } else { $null }
            auth_mode   = if ($Miner) { $Miner.auth_mode }  else { $null }
            adapter     = $DiscoveryMeta.adapter
            subnet      = $DiscoveryMeta.subnet
            total_hosts = $DiscoveryMeta.total_hosts
        }
    } | ConvertTo-Json -Depth 5

    Set-Content -Path (Join-Path $InstallDir "config.json") -Value $config -Encoding Ascii
}

# ── Sequential endpoint check — used for local IP and cached IP ───────────────
function Test-MinerEndpoint {
    param([string]$Ip, [int]$PreferredPort = 0)

    $uriPath = "/cgi-bin/stats.cgi"
    $ports   = @()
    if ($PreferredPort -gt 0) { $ports += $PreferredPort }
    $ports += 8080, 80
    $ports = $ports | Select-Object -Unique

    foreach ($port in $ports) {
        $url = "http://$Ip`:$port$uriPath"
        Write-Log "INFO" "Checking ${Ip}:$port"

        try {
            $res = Invoke-WebRequest -Uri $url -TimeoutSec $EndpointTimeoutSec -UseBasicParsing -ErrorAction Stop
            if ($res.StatusCode -eq 200) {
                $json = $res.Content | ConvertFrom-Json -ErrorAction Stop
                if ($json.STATS -and @($json.STATS).Count -gt 0) {
                    $minerType = if ($json.INFO -and $json.INFO.type) { $json.INFO.type } else { "unknown" }
                    Write-Log "INFO" "Miner confirmed at ${Ip}:$port (type=$minerType)"
                    return [pscustomobject]@{ miner_ip = $Ip; miner_port = $port; miner_type = $minerType; auth_mode = "open" }
                }
                Write-Log "WARN" "200 OK but no STATS from ${Ip}:$port"
            }
        }
        catch {
            $resp = $_.Exception.Response
            if ($resp -and [int]$resp.StatusCode -eq 401) {
                $header = $resp.Headers["WWW-Authenticate"]
                if ($header) {
                    try {
                        # Parse digest challenge inline
                        $ch = @{}
                        foreach ($m in [regex]::Matches($header, '(\w+)=(?:"([^"]+)"|([^\s,]+))')) {
                            $ch[$m.Groups[1].Value] = if ($m.Groups[2].Value) { $m.Groups[2].Value } else { $m.Groups[3].Value }
                        }
                        # Build digest response inline
                        $md5    = [System.Security.Cryptography.MD5]::Create()
                        $toHex  = { param($t) ($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($t)) | ForEach-Object { $_.ToString("x2") }) -join "" }
                        $ha1    = & $toHex "$MinerUser`:$($ch.realm)`:$MinerPass"
                        $ha2    = & $toHex "GET`:$uriPath"
                        $nc     = "00000001"
                        $cnonce = ([guid]::NewGuid().ToString("N")).Substring(0, 16)
                        $rHash  = & $toHex "$ha1`:$($ch.nonce)`:$nc`:$cnonce`:auth`:$ha2"
                        $authHdr = 'Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", qop=auth, nc={4}, cnonce="{5}", response="{6}"' -f $MinerUser, $ch.realm, $ch.nonce, $uriPath, $nc, $cnonce, $rHash
                        $md5.Dispose()

                        $authed = Invoke-WebRequest -Uri $url -Headers @{ Authorization = $authHdr } -TimeoutSec $EndpointTimeoutSec -UseBasicParsing -ErrorAction Stop
                        $json   = $authed.Content | ConvertFrom-Json -ErrorAction Stop
                        if ($authed.StatusCode -eq 200 -and $json.STATS -and @($json.STATS).Count -gt 0) {
                            $minerType = if ($json.INFO -and $json.INFO.type) { $json.INFO.type } else { "unknown" }
                            Write-Log "INFO" "Miner confirmed at ${Ip}:$port via digest (type=$minerType)"
                            return [pscustomobject]@{ miner_ip = $Ip; miner_port = $port; miner_type = $minerType; auth_mode = "digest" }
                        }
                    }
                    catch {
                        Write-Log "WARN" "Digest auth failed for ${Ip}:$port"
                    }
                }
            }
        }
    }

    return $null
}

# ── Parallel scan — each runspace does ping + verify together.
#    Stops submitting new work the moment a miner is confirmed. ────────────────
function Invoke-ParallelMinerScan {
    param(
        [string[]]$Ips,
        [int]$PingTimeoutMs,
        [int]$Throttle,
        [int]$EndpointTimeoutSec,
        [string]$MinerUser,
        [string]$MinerPass
    )

    # Self-contained: ping then immediately verify — no shared state needed
    $runspaceScript = {
        param($TargetIp, $PingMs, $HttpSec, $User, $Pass)

        # Step 1: ping
        $ping = [System.Net.NetworkInformation.Ping]::new()
        try {
            $reply = $ping.Send($TargetIp, $PingMs)
            if (-not ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)) {
                return $null
            }
        }
        finally { $ping.Dispose() }

        # Step 2: verify miner endpoint
        $uriPath = "/cgi-bin/stats.cgi"
        foreach ($port in @(8080, 80)) {
            $url = "http://$TargetIp`:$port$uriPath"
            try {
                $res = Invoke-WebRequest -Uri $url -TimeoutSec $HttpSec -UseBasicParsing -ErrorAction Stop
                if ($res.StatusCode -eq 200) {
                    $json = $res.Content | ConvertFrom-Json -ErrorAction Stop
                    if ($json.STATS -and @($json.STATS).Count -gt 0) {
                        $mt = if ($json.INFO -and $json.INFO.type) { $json.INFO.type } else { "unknown" }
                        return [pscustomobject]@{ miner_ip = $TargetIp; miner_port = $port; miner_type = $mt; auth_mode = "open" }
                    }
                }
            }
            catch {
                $resp = $_.Exception.Response
                if ($resp -and [int]$resp.StatusCode -eq 401) {
                    $hdr = $resp.Headers["WWW-Authenticate"]
                    if ($hdr) {
                        try {
                            $ch = @{}
                            foreach ($m in [regex]::Matches($hdr, '(\w+)=(?:"([^"]+)"|([^\s,]+))')) {
                                $ch[$m.Groups[1].Value] = if ($m.Groups[2].Value) { $m.Groups[2].Value } else { $m.Groups[3].Value }
                            }
                            $md5    = [System.Security.Cryptography.MD5]::Create()
                            $toHex  = { param($t) ($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($t)) | ForEach-Object { $_.ToString("x2") }) -join "" }
                            $ha1    = & $toHex "$User`:$($ch.realm)`:$Pass"
                            $ha2    = & $toHex "GET`:$uriPath"
                            $nc     = "00000001"
                            $cn     = ([guid]::NewGuid().ToString("N")).Substring(0, 16)
                            $rHash  = & $toHex "$ha1`:$($ch.nonce)`:$nc`:$cn`:auth`:$ha2"
                            $auth   = 'Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", qop=auth, nc={4}, cnonce="{5}", response="{6}"' -f $User, $ch.realm, $ch.nonce, $uriPath, $nc, $cn, $rHash
                            $md5.Dispose()
                            $a2 = Invoke-WebRequest -Uri $url -Headers @{ Authorization = $auth } -TimeoutSec $HttpSec -UseBasicParsing -ErrorAction Stop
                            $j2 = $a2.Content | ConvertFrom-Json -ErrorAction Stop
                            if ($a2.StatusCode -eq 200 -and $j2.STATS -and @($j2.STATS).Count -gt 0) {
                                $mt = if ($j2.INFO -and $j2.INFO.type) { $j2.INFO.type } else { "unknown" }
                                return [pscustomobject]@{ miner_ip = $TargetIp; miner_port = $port; miner_type = $mt; auth_mode = "digest" }
                            }
                        }
                        catch {}
                    }
                }
            }
        }
        return $null
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
    $pool.Open()

    $pending   = [System.Collections.ArrayList]::new()
    $submitted = 0
    $checked   = 0
    $nextLog   = 100
    $found     = $null

    try {
        while (($submitted -lt $Ips.Count -or $pending.Count -gt 0) -and -not $found) {

            # Submit new jobs only while no miner found yet
            while ($submitted -lt $Ips.Count -and $pending.Count -lt $Throttle -and -not $found) {
                $ip = $Ips[$submitted++]
                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddScript($runspaceScript).AddArgument($ip).AddArgument($PingTimeoutMs).AddArgument($EndpointTimeoutSec).AddArgument($MinerUser).AddArgument($MinerPass)
                $handle = $ps.BeginInvoke()
                [void]$pending.Add([pscustomobject]@{ PS = $ps; Handle = $handle })
            }

            # Harvest completed runspaces
            for ($i = $pending.Count - 1; $i -ge 0; $i--) {
                $item = $pending[$i]
                if ($item.Handle.IsCompleted) {
                    try {
                        $results = @($item.PS.EndInvoke($item.Handle))
                        if ($results.Count -gt 0 -and $results[0] -and -not $found) {
                            $found = $results[0]
                        }
                    }
                    catch {}
                    finally {
                        $item.PS.Dispose()
                        $pending.RemoveAt($i)
                    }
                    $checked++
                    if ($checked -ge $nextLog -or ($submitted -eq $Ips.Count -and $pending.Count -eq 0)) {
                        Write-Log "INFO" "Scan progress: checked=$checked / submitted=$submitted"
                        $nextLog += 100
                    }
                }
            }

            if ($found) { break }
            Start-Sleep -Milliseconds 25
        }
    }
    finally {
        foreach ($item in $pending) { try { $item.PS.Dispose() } catch {} }
        $pool.Close()
        $pool.Dispose()
    }

    return $found
}

# ── Main discovery logic ──────────────────────────────────────────────────────
function Discover-Miner {
    param([string]$InstallDir)

    $cfg     = Get-PrimaryIPv4Config
    $ip      = $cfg.IPv4Address.IPAddress
    $prefix  = $cfg.IPv4Address.PrefixLength
    $gateway = $cfg.IPv4DefaultGateway.NextHop

    Write-Log "INFO" "Adapter: $($cfg.InterfaceAlias)"
    Write-Log "INFO" "Local IP: $ip"
    Write-Log "INFO" "Subnet: $ip/$prefix"

    $meta = @{ adapter = $cfg.InterfaceAlias; subnet = "$ip/$prefix"; total_hosts = 0 }

    # 1. Try cached IP first (re-installs / agent restarts)
    $cached = Get-CachedDiscovery -InstallDir $InstallDir
    if ($cached -and $cached.miner_ip) {
        Write-Log "INFO" "Trying cached miner: $($cached.miner_ip):$($cached.miner_port)"
        $miner = Test-MinerEndpoint -Ip $cached.miner_ip -PreferredPort ([int]($cached.miner_port))
        if ($miner) { return [pscustomobject]@{ Miner = $miner; Meta = $meta } }
        Write-Log "WARN" "Cached miner not reachable, continuing scan"
    }

    # 2. Try local machine — catches mock-miner and same-box setups
    Write-Log "INFO" "Trying local IP: $ip"
    $miner = Test-MinerEndpoint -Ip $ip -PreferredPort 8080
    if ($miner) {
        Write-Log "INFO" "Miner found on local machine: $($miner.miner_ip):$($miner.miner_port)"
        return [pscustomobject]@{ Miner = $miner; Meta = $meta }
    }

    # 3. Full parallel scan — exits immediately when first miner is confirmed
    $hosts = @(Get-SubnetHosts -Ip $ip -PrefixLength $prefix | Where-Object { $_ -ne $ip -and $_ -ne $gateway })
    $meta.total_hosts = $hosts.Count
    Write-Log "INFO" "Scanning $($hosts.Count) hosts — will stop on first miner found..."

    $miner = Invoke-ParallelMinerScan `
        -Ips $hosts `
        -PingTimeoutMs $PingTimeoutMs `
        -Throttle $PingThrottle `
        -EndpointTimeoutSec $EndpointTimeoutSec `
        -MinerUser $MinerUser `
        -MinerPass $MinerPass

    if ($miner) {
        Write-Log "INFO" "Miner found: $($miner.miner_ip):$($miner.miner_port) (type=$($miner.miner_type))"
    } else {
        Write-Log "WARN" "No miner found on network"
    }

    return [pscustomobject]@{ Miner = $miner; Meta = $meta }
}

# ── Install ───────────────────────────────────────────────────────────────────
try {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $machineId = [guid]::NewGuid().ToString()

    Write-Log "INFO" "Starting network scan..."
    $result = Discover-Miner -InstallDir $InstallDir
    $miner  = $result.Miner

    Save-DiscoveryResult `
        -InstallDir $InstallDir `
        -Payload $Payload `
        -BackendUrl $BackendUrl `
        -MachineId $machineId `
        -Miner $miner `
        -DiscoveryMeta $result.Meta

    Write-Log "INFO" "Downloading agent..."
    $agentDest = Join-Path $InstallDir "agent.js"
    Invoke-WebRequest -Uri $AgentUrl -OutFile $agentDest

    Write-Log "INFO" "Downloading mock telemetry..."
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