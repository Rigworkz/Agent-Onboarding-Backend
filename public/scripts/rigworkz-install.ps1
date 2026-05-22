param(
    [string]$Payload,
    [string]$BackendUrl = "http://35.224.207.37:5000",
    [string]$AgentUrl = "http://35.224.207.37:5000/scripts/agent.js",
    [string]$InstallDir = "C:\rigworkz-agent",
    [string]$MinerUser = "root",
    [string]$MinerPass = "root",
    # Explicit miner IP override (comma-separated for multiple).
    # When provided, the LAN scan is skipped entirely.
    # Examples:
    #   -MinerIp "10.5.51.201"
    #   -MinerIp "10.5.51.201,10.5.51.202,10.5.51.203"
    [string]$MinerIp = "",
    [int]$TcpConnectTimeoutMs = 400,
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
    if (-not (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
        throw "Get-NetIPConfiguration unavailable (requires Windows 8+). Re-run with -MinerIp <ip> to bypass auto-discovery."
    }

    $cfg = Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4Address -and
            $_.IPv4DefaultGateway -and
            $_.NetAdapter.Status -eq "Up" -and
            $_.InterfaceAlias -notmatch "Tailscale|Loopback"
        } |
        Select-Object -First 1

    if (-not $cfg) {
        throw "No active IPv4 adapter found. Re-run with -MinerIp <ip> to bypass auto-discovery."
    }

    return $cfg
}

function Get-MaskBytesFromPrefixLength {
    param([int]$PrefixLength)
    $mask = New-Object byte[] 4
    for ($i = 0; $i -lt 4; $i++) {
        $bits = $PrefixLength - ($i * 8)
        if ($bits -ge 8)      { $mask[$i] = 255 }
        elseif ($bits -le 0)  { $mask[$i] = 0   }
        else                  { $mask[$i] = [byte](256 - [int][math]::Pow(2, 8 - $bits)) }
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
    param([string]$Ip, [int]$PrefixLength)

    $ipBytes   = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    $maskBytes = Get-MaskBytesFromPrefixLength -PrefixLength $PrefixLength

    $networkBytes  = New-Object byte[] 4
    $wildcardBytes = New-Object byte[] 4
    for ($i = 0; $i -lt 4; $i++) {
        $networkBytes[$i]  = $ipBytes[$i] -band $maskBytes[$i]
        $wildcardBytes[$i] = 255 - $maskBytes[$i]
    }

    $networkInt  = Convert-BytesToUInt32 -Bytes $networkBytes
    $wildcardInt = Convert-BytesToUInt32 -Bytes $wildcardBytes
    $start = [uint64]$networkInt + 1
    $end   = [uint64]$networkInt + [uint64]$wildcardInt - 1

    $hosts = New-Object System.Collections.Generic.List[string]
    for ($n = $start; $n -le $end; $n++) {
        $hosts.Add((Convert-UInt32ToIp -Value ([uint32]$n)))
    }
    return $hosts
}

function Get-Md5Hex {
    param([string]$Text)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash  = $md5.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally { $md5.Dispose() }
}

# DER/ASN.1 helpers for RSA key export
function ConvertTo-DerLength([int]$n) {
    if ($n -lt 0x80)  { return [byte[]]@($n) }
    if ($n -lt 0x100) { return [byte[]]@(0x81, $n) }
    return [byte[]]@(0x82, ($n -shr 8), ($n -band 0xFF))
}

function ConvertTo-DerInteger([byte[]]$b) {
    $i = 0
    while ($i -lt $b.Length - 1 -and $b[$i] -eq 0) { $i++ }
    $b = $b[$i..($b.Length - 1)]
    if ($b[0] -band 0x80) { $b = @([byte]0x00) + $b }
    return @([byte]0x02) + (ConvertTo-DerLength $b.Length) + $b
}

function ConvertTo-DerSequence([byte[]]$b) {
    return @([byte]0x30) + (ConvertTo-DerLength $b.Length) + $b
}

function ConvertTo-Pkcs1PrivateKeyPem([System.Security.Cryptography.RSAParameters]$p) {
    $der = ConvertTo-DerSequence (
        [byte[]]@(0x02, 0x01, 0x00) +
        (ConvertTo-DerInteger $p.Modulus)  +
        (ConvertTo-DerInteger $p.Exponent) +
        (ConvertTo-DerInteger $p.D)        +
        (ConvertTo-DerInteger $p.P)        +
        (ConvertTo-DerInteger $p.Q)        +
        (ConvertTo-DerInteger $p.DP)       +
        (ConvertTo-DerInteger $p.DQ)       +
        (ConvertTo-DerInteger $p.InverseQ)
    )
    $b64 = [Convert]::ToBase64String($der, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN RSA PRIVATE KEY-----`n$b64`n-----END RSA PRIVATE KEY-----"
}

function ConvertTo-SpkiPublicKey([System.Security.Cryptography.RSAParameters]$p) {
    $rsaPub    = ConvertTo-DerSequence ((ConvertTo-DerInteger $p.Modulus) + (ConvertTo-DerInteger $p.Exponent))
    $bitString = @([byte]0x03) + (ConvertTo-DerLength ($rsaPub.Length + 1)) + @([byte]0x00) + $rsaPub
    $oid       = [byte[]]@(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00)
    $algId     = ConvertTo-DerSequence $oid
    $spkiDer   = ConvertTo-DerSequence ($algId + $bitString)
    return @{
        Pem    = "-----BEGIN PUBLIC KEY-----`n$([Convert]::ToBase64String($spkiDer, [Base64FormattingOptions]::InsertLineBreaks))`n-----END PUBLIC KEY-----"
        Base64 = [Convert]::ToBase64String($spkiDer)
    }
}

# ─── ProbeScript ─────────────────────────────────────────────────────────────
# Runs inside a Start-Job process. Returns a miner object if the host is a
# valid Antminer, or $null otherwise.
$ProbeScript = {
    param(
        [string]$Ip,
        [int]$Port,
        [int]$EndpointTimeoutMs,
        [string]$MinerUser,
        [string]$MinerPass
    )

    function Get-Md5Hex([string]$text) {
        $md5 = [System.Security.Cryptography.MD5]::Create()
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
            $hash  = $md5.ComputeHash($bytes)
            return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
        }
        finally { $md5.Dispose() }
    }

    function Parse-AuthChallenge([string]$header) {
        $out = @{}
        foreach ($m in [regex]::Matches($header, '(\w+)=(?:"([^"]+)"|([^\s,]+))')) {
            $out[$m.Groups[1].Value] = if ($m.Groups[2].Value) { $m.Groups[2].Value } else { $m.Groups[3].Value }
        }
        return $out
    }

    function Build-DigestHeader([string]$method, [string]$uriPath, [hashtable]$ch, [string]$user, [string]$pass) {
        $ha1 = Get-Md5Hex "$user`:$($ch.realm)`:$pass"
        $ha2 = Get-Md5Hex "$method`:$uriPath"
        if ($ch.qop -and $ch.qop -like "*auth*") {
            $nc     = "00000001"
            $cnonce = ([guid]::NewGuid().ToString("N")).Substring(0, 16)
            $resp   = Get-Md5Hex "$ha1`:$($ch.nonce)`:$nc`:$cnonce`:auth`:$ha2"
            return ('Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", qop=auth, nc={4}, cnonce="{5}", response="{6}"' -f `
                $user, $ch.realm, $ch.nonce, $uriPath, $nc, $cnonce, $resp)
        }
        $resp = Get-Md5Hex "$ha1`:$($ch.nonce)`:$ha2"
        return ('Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", response="{4}"' -f `
            $user, $ch.realm, $ch.nonce, $uriPath, $resp)
    }

    function Invoke-RawGet([string]$url, [string]$authHeader = $null, [int]$timeoutMs = 5000) {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method  = "GET"
        $req.Timeout = $timeoutMs
        $req.AllowAutoRedirect = $false
        if ($authHeader) { $req.Headers["Authorization"] = $authHeader }

        try {
            $resp   = $req.GetResponse()
            $stream = $resp.GetResponseStream()
            $body   = (New-Object System.IO.StreamReader $stream).ReadToEnd()
            $resp.Close()
            return @{ ok = $true; body = $body }
        }
        catch [System.Net.WebException] {
            $webResp = $_.Exception.Response
            if ($null -eq $webResp) { return @{ ok = $false; statusCode = 0; wwwAuth = $null } }
            $code    = [int]$webResp.StatusCode
            $wwwAuth = $webResp.Headers["WWW-Authenticate"]
            $webResp.Close()
            return @{ ok = $false; statusCode = $code; wwwAuth = $wwwAuth }
        }
        catch {
            return @{ ok = $false; statusCode = 0; wwwAuth = $null }
        }
    }

    $uriPath = "/cgi-bin/stats.cgi"
    $url     = "http://$Ip`:$Port$uriPath"

    $probe = Invoke-RawGet -url $url -timeoutMs $EndpointTimeoutMs

    if ($probe.ok) {
        try {
            $json = $probe.body | ConvertFrom-Json -ErrorAction Stop
            if ($json -and $json.STATS -and @($json.STATS).Count -gt 0) {
                $minerType = if ($json.INFO.type) { $json.INFO.type } else { "unknown" }
                return [pscustomobject]@{ miner_ip=$Ip; miner_port=$Port; miner_type=$minerType; auth_mode="open" }
            }
        }
        catch {}
        return $null
    }

    if ($probe.statusCode -ne 401 -or -not $probe.wwwAuth) {
        return $null
    }

    $ch      = Parse-AuthChallenge $probe.wwwAuth
    $authHdr = Build-DigestHeader "GET" $uriPath $ch $MinerUser $MinerPass
    $authed  = Invoke-RawGet -url $url -authHeader $authHdr -timeoutMs $EndpointTimeoutMs

    if (-not $authed.ok) { return $null }

    try {
        $json = $authed.body | ConvertFrom-Json -ErrorAction Stop
        if ($json -and $json.STATS -and @($json.STATS).Count -gt 0) {
            $minerType = if ($json.INFO.type) { $json.INFO.type } else { "unknown" }
            return [pscustomobject]@{ miner_ip=$Ip; miner_port=$Port; miner_type=$minerType; auth_mode="digest" }
        }
    }
    catch {}

    return $null
}

function Get-OrderedPorts {
    param([int]$PreferredPort = 0, [int[]]$Ports)
    $ordered = New-Object System.Collections.Generic.List[int]
    if ($PreferredPort -gt 0) { [void]$ordered.Add($PreferredPort) }
    foreach ($p in $Ports) {
        if ($p -gt 0 -and -not $ordered.Contains($p)) { [void]$ordered.Add($p) }
    }
    return ,$ordered.ToArray()
}

# ─── Test-MinerEndpoint ──────────────────────────────────────────────────────
# Probes one IP across all candidate ports in parallel.
# Returns the first successful miner object, or $null.
function Test-MinerEndpoint {
    param([string]$Ip, [int]$PreferredPort = 0)

    $ports     = Get-OrderedPorts -PreferredPort $PreferredPort -Ports $MinerPorts
    $timeoutMs = $EndpointTimeoutSec * 1000
    $jobs      = @()

    foreach ($port in $ports) {
        $jobs += Start-Job -ScriptBlock $ProbeScript `
                           -ArgumentList $Ip, $port, $timeoutMs, $MinerUser, $MinerPass
    }

    try {
        while ($jobs.Count -gt 0) {
            $completedJobs = @(Wait-Job -Job $jobs -Any)
            foreach ($completedJob in $completedJobs) {
                $result = $null
                try { $result = Receive-Job -Job $completedJob -ErrorAction SilentlyContinue } catch {}
                Remove-Job -Job $completedJob -Force -ErrorAction SilentlyContinue
                $jobs = @($jobs | Where-Object { $_.Id -ne $completedJob.Id })
                if ($result) {
                    foreach ($j in $jobs) {
                        Stop-Job  -Job $j -ErrorAction SilentlyContinue
                        Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
                    }
                    return $result
                }
            }
        }
    }
    finally {
        foreach ($j in $jobs) { Remove-Job -Job $j -Force -ErrorAction SilentlyContinue }
    }

    return $null
}

function Get-TcpAliveHosts {
    param([string[]]$Hosts, [int[]]$Ports, [int]$TimeoutMs)

    $tcpBlock = {
        param([string]$Ip, [int[]]$Ports, [int]$TimeoutMs)
        foreach ($port in $Ports) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
                $ar = $tcp.BeginConnect($Ip, $port, $null, $null)
                if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tcp.Connected) {
                    return $Ip
                }
            }
            catch {}
            finally { try { $tcp.Close() } catch {} }
        }
        return $null
    }

    $pool = [RunspaceFactory]::CreateRunspacePool(1, [Math]::Min($Hosts.Count, 300))
    $pool.Open()

    $handles = [System.Collections.Generic.List[object]]::new()
    foreach ($h in $Hosts) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($tcpBlock).AddArgument($h).AddArgument($Ports).AddArgument($TimeoutMs)
        $handles.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
    }

    $alive = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $handles) {
        try {
            $res = $entry.PS.EndInvoke($entry.Handle)
            if ($res -and $res[0]) { [void]$alive.Add($res[0]) }
        }
        catch {}
        finally { $entry.PS.Dispose() }
    }

    $pool.Close()
    $pool.Dispose()
    return $alive
}

# ─── Discover-AllMiners ──────────────────────────────────────────────────────
# CHANGED from original: probes EVERY alive host rather than stopping at the
# first hit. Returns all confirmed miners plus scan metadata.
function Discover-AllMiners {
    param([string]$InstallDir)

    $cfg     = Get-PrimaryIPv4Config
    $ip      = $cfg.IPv4Address.IPAddress
    $prefix  = $cfg.IPv4Address.PrefixLength
    $gateway = $cfg.IPv4DefaultGateway.NextHop

    Write-Log "INFO" "Adapter    : $($cfg.InterfaceAlias)"
    Write-Log "INFO" "Local IP   : $ip"
    Write-Log "INFO" "Subnet     : $ip/$prefix"
    Write-Host ""

    $meta = @{
        method        = "local-first + tcp-scan"
        adapter       = $cfg.InterfaceAlias
        subnet        = "$ip/$prefix"
        total_hosts   = 0
        checked_hosts = 0
        alive_hosts   = 0
    }

    $miners = [System.Collections.Generic.List[object]]::new()

    # Check local machine first
    Write-Log "INFO" "Checking local machine (ports $($MinerPorts -join ' / ')) ..."
    $localMiner = Test-MinerEndpoint -Ip $ip -PreferredPort 8080
    if ($localMiner) {
        Write-Log "OK" "Miner found on local machine - $($localMiner.miner_ip):$($localMiner.miner_port)"
        [void]$miners.Add($localMiner)
    }

    # Parallel TCP sweep of the whole subnet
    $allHosts = @(Get-SubnetHosts -Ip $ip -PrefixLength $prefix |
                  Where-Object { $_ -ne $ip -and $_ -ne $gateway })
    $meta.total_hosts = $allHosts.Count

    Write-Host ""
    Write-Log "INFO" "Scanning $($allHosts.Count) hosts on ports $($MinerPorts -join '/') ..."

    $aliveHosts     = @(Get-TcpAliveHosts -Hosts $allHosts -Ports $MinerPorts -TimeoutMs $TcpConnectTimeoutMs)
    $meta.alive_hosts = $aliveHosts.Count

    if ($aliveHosts.Count -eq 0) {
        Write-Log "WARN" "No hosts with open miner ports found on LAN"
    }
    else {
        Write-Log "INFO" "$($aliveHosts.Count) host(s) with open ports — verifying each as a miner ..."
        $checked = 0

        foreach ($candidate in $aliveHosts) {
            $checked++
            # Skip if we already found this IP (e.g. local check above)
            $alreadyFound = $miners | Where-Object { $_.miner_ip -eq $candidate }
            if ($alreadyFound) { continue }

            Write-Log "INFO" "  [$checked/$($aliveHosts.Count)] Probing $candidate ..."
            $miner = Test-MinerEndpoint -Ip $candidate
            if ($miner) {
                Write-Log "OK" "  Miner confirmed: $($miner.miner_ip):$($miner.miner_port) ($($miner.miner_type), auth: $($miner.auth_mode))"
                [void]$miners.Add($miner)
            }
        }

        $meta.checked_hosts = $checked
    }

    return [pscustomobject]@{ Miners = $miners.ToArray(); Meta = $meta }
}

# ─── Resolve-AllMiners ───────────────────────────────────────────────────────
# Handles explicit IP override (comma-separated) OR runs LAN discovery.
function Resolve-AllMiners {
    param([string]$ExplicitIp, [string]$InstallDir)

    if ($ExplicitIp) {
        $ipList = $ExplicitIp -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

        Write-Log "INFO" "Manual miner IP(s) provided: $($ipList -join ', ') — skipping LAN scan"
        Write-Host ""

        $miners = [System.Collections.Generic.List[object]]::new()
        $meta   = @{
            method        = "manual-override"
            adapter       = "manual-override"
            subnet        = "manual-override"
            total_hosts   = $ipList.Count
            checked_hosts = 0
            alive_hosts   = 0
        }

        foreach ($singleIp in $ipList) {
            $meta.checked_hosts++
            Write-Log "INFO" "  Probing $singleIp ..."
            $probed = Test-MinerEndpoint -Ip $singleIp
            if ($probed) {
                $meta.alive_hosts++
                [void]$miners.Add($probed)
                Write-Log "OK" "  Miner confirmed: $singleIp"
            }
            else {
                Write-Log "WARN" "  Probe to $singleIp failed — will write config anyway; agent will retry"
                # Write a stub entry so the agent still attempts to connect
                [void]$miners.Add([pscustomobject]@{
                    miner_ip   = $singleIp
                    miner_port = 80
                    miner_type = "unknown"
                    auth_mode  = "unknown"
                })
            }
        }

        return [pscustomobject]@{ Miners = $miners.ToArray(); Meta = $meta }
    }

    return Discover-AllMiners -InstallDir $InstallDir
}

# ─── Save-MultiRigConfig ─────────────────────────────────────────────────────
# Writes config.json with a machines[] array (one entry per discovered miner).
# Each machine gets its own UUID so the agent and backend can address them
# independently. The single RSA public key is shared across all machines in
# this farm (same operator wallet).
function Save-MultiRigConfig {
    param(
        [string]$InstallDir,
        [string]$Payload,
        [string]$BackendUrl,
        [string]$PublicKeyB64,
        [object[]]$Miners,
        [object]$Meta,
        [hashtable]$MachineIds   # ip -> machine_id mapping built during registration
    )

    $machines = @()
    foreach ($miner in $Miners) {
        $mid = $MachineIds[$miner.miner_ip]
        $machines += @{
            machine_id = $mid
            miner_ip   = $miner.miner_ip
            miner_port = $miner.miner_port
            miner_type = $miner.miner_type
            auth_mode  = $miner.auth_mode
        }
    }

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        public_key = $PublicKeyB64
        machines   = $machines
        discovery  = @{
            method        = if ($Meta.method) { $Meta.method } else { "local-first + tcp-scan" }
            status        = if ($Miners.Count -gt 0) { "found" } else { "not_found" }
            scanned_at    = (Get-Date).ToString("o")
            adapter       = $Meta.adapter
            subnet        = $Meta.subnet
            total_hosts   = $Meta.total_hosts
            checked_hosts = $Meta.checked_hosts
            alive_hosts   = $Meta.alive_hosts
            miner_count   = $Miners.Count
        }
    } | ConvertTo-Json -Depth 6

    Set-Content -Path (Join-Path $InstallDir "config.json") -Value $config -Encoding Ascii
}

function Test-NodeVersion {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        return @{ ok = $false; reason = "Node.js is not installed or not in PATH" }
    }
    try {
        $raw   = (& node --version) 2>$null
        $clean = $raw.TrimStart('v').Trim()
        $parts = $clean.Split('.')
        $major = [int]$parts[0]
        $minor = if ($parts.Count -gt 1) { [int]$parts[1] } else { 0 }
        if ($major -lt 14 -or ($major -eq 14 -and $minor -lt 17)) {
            return @{ ok = $false; reason = "Node.js v$clean is too old (need 14.17+)" }
        }
        return @{ ok = $true; version = $raw }
    }
    catch {
        return @{ ok = $false; reason = "Failed to query Node.js: $($_.Exception.Message)" }
    }
}

# ─── Main ────────────────────────────────────────────────────────────────────
try {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor DarkCyan
    Write-Host "   RigWorkz Agent Installer  (multi-rig edition)" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor DarkCyan
    Write-Host ""

    # ── Generate RSA key pair (shared for this farm) ──────────────────────────
    Write-Log "INFO" "Generating RSA key pair ..."
    $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    try {
        $rsaParams     = $rsa.ExportParameters($true)
        $privateKeyPem = ConvertTo-Pkcs1PrivateKeyPem -p $rsaParams
        $pubKey        = ConvertTo-SpkiPublicKey -p $rsaParams
        $publicKeyPem  = $pubKey.Pem
        $publicKeyB64  = $pubKey.Base64
    }
    finally { $rsa.Dispose() }

    $privateKeyPath = Join-Path $InstallDir "private_key.pem"
    Set-Content -Path $privateKeyPath -Value $privateKeyPem -Encoding Ascii
    cmd /c "icacls `"$privateKeyPath`" /inheritance:r /grant:r `"${env:USERNAME}:F`"" > $null 2>&1
    Set-Content -Path (Join-Path $InstallDir "public_key.pem") -Value $publicKeyPem -Encoding Ascii
    Write-Log "OK" "RSA key pair ready"

    # ── Decode payload early (needed for installToken) ────────────────────────
    $decoded      = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload))
    $installToken = ($decoded | ConvertFrom-Json).installToken
    if (-not $installToken) { throw "installToken missing from payload" }

    # ── Discover all miners ───────────────────────────────────────────────────
    Write-Log "INFO" "Resolving miner endpoint(s) ..."
    Write-Host ""

    $result = Resolve-AllMiners -ExplicitIp $MinerIp -InstallDir $InstallDir
    $miners  = @($result.Miners)

    Write-Host ""

    if ($miners.Count -eq 0) {
        Write-Log "WARN" "No miners found on this network."
        Write-Log "INFO" "Tip: re-run with -MinerIp <ip1,ip2,...> if miners are on a different subnet."
        # Still continue — user might want the agent installed and configured manually.
    }
    else {
        Write-Log "OK" "Found $($miners.Count) miner(s):"
        foreach ($m in $miners) {
            Write-Log "OK" "  $($m.miner_ip):$($m.miner_port)  type=$($m.miner_type)  auth=$($m.auth_mode)"
        }
    }

    # ── Register every miner with the backend ─────────────────────────────────
    # Each miner gets a unique machine_id UUID. All share the same RSA public
    # key (one key pair per farm). installToken is reused for every call;
    # the backend must not mark it used until all registrations are done.
    Write-Host ""
    Write-Log "INFO" "Registering $($miners.Count) miner(s) with backend ..."

    $machineIds     = @{}   # ip -> machine_id
    $registeredCount = 0

    foreach ($miner in $miners) {
        $machineId = [guid]::NewGuid().ToString()

        try {
            $registerBody = @{
                installToken = $installToken
                machineId    = $machineId
                publicKey    = $publicKeyPem
                minerIp      = $miner.miner_ip
                minerPort    = $miner.miner_port
                minerType    = $miner.miner_type
            } | ConvertTo-Json

            $registerResponse = Invoke-WebRequest `
                -Uri         "$BackendUrl/api/register" `
                -Method      POST `
                -Body        $registerBody `
                -ContentType "application/json" `
                -UseBasicParsing `
                -ErrorAction Stop

            $registerResult = $registerResponse.Content | ConvertFrom-Json
            if ($registerResult.success -ne $true) {
                throw "Backend rejected: $($registerResult.message)"
            }

            $machineIds[$miner.miner_ip] = $machineId
            $registeredCount++
            Write-Log "OK" "  Registered $($miner.miner_ip) → machine_id: $machineId"
        }
        catch {
            Write-Log "ERR" "  Failed to register $($miner.miner_ip): $($_.Exception.Message)"
            # Assign a local-only machine_id so the agent can still poll the miner
            # even if the backend registration failed; telemetry will be retried.
            $machineIds[$miner.miner_ip] = [guid]::NewGuid().ToString()
        }
    }

    Write-Host ""
    Write-Log "INFO" "Registration complete: $registeredCount / $($miners.Count) succeeded"

    # ── Write multi-machine config.json ───────────────────────────────────────
    Write-Log "INFO" "Saving config ..."
    Save-MultiRigConfig `
        -InstallDir  $InstallDir `
        -Payload     $Payload `
        -BackendUrl  $BackendUrl `
        -PublicKeyB64 $publicKeyB64 `
        -Miners      $miners `
        -Meta        $result.Meta `
        -MachineIds  $machineIds

    # ── Download agent ────────────────────────────────────────────────────────
    Write-Log "INFO" "Downloading agent ..."
    $agentDest = Join-Path $InstallDir "agent.js"
    Invoke-WebRequest -Uri $AgentUrl -OutFile $agentDest

    $nodeCheck = Test-NodeVersion
    if (-not $nodeCheck.ok) {
        Write-Host ""
        Write-Log "ERR" "$($nodeCheck.reason). Install Node.js >= 14.17 from https://nodejs.org then start the agent manually: node `"$agentDest`""
        exit 1
    }
    Write-Log "INFO" "Node.js $($nodeCheck.version) detected"

    # ── Launch agent ──────────────────────────────────────────────────────────
    Write-Log "INFO" "Launching agent process ..."
    Start-Process -FilePath "node" -ArgumentList "`"$agentDest`"" -WorkingDirectory $InstallDir

    Write-Host ""
    Write-Log "OK" "Agent is running — monitoring $($miners.Count) miner(s). All done."
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Log "ERR" "Installation failed: $($_.Exception.Message)"
    exit 1
}