param(
    [string]$Payload,
    [string]$BackendUrl = "http://35.224.207.37:5000",
    [string]$AgentUrl = "http://35.224.207.37:5000/scripts/agent.js",
    [string]$InstallDir = "C:\rigworkz-agent",
    [string]$MinerUser = "root",
    [string]$MinerPass = "root",
    # Explicit miner IP override. When provided, the LAN scan is skipped and
    # the supplied IP is written directly to config.json. Use this for:
    #   - remote installs over Tailscale where the laptop's primary subnet
    #     differs from the miner's subnet
    #   - multi-NIC laptops where auto-detection picks the wrong adapter
    #   - operators who already know the miner IP and want to skip the scan
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
        [string]$PublicKey,
        [object]$Miner,
        [object]$Meta
    )

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        machine_id = $MachineId
        public_key = $PublicKey
        miner_ip   = if ($Miner) { $Miner.miner_ip }   else { $null }
        miner_port = if ($Miner) { $Miner.miner_port } else { $null }
        discovery  = @{
            method        = if ($Meta.method) { $Meta.method } else { "local-first + tcp-scan" }
            status        = if ($Miner) { "found" } else { "not_found" }
            scanned_at    = (Get-Date).ToString("o")
            miner_type    = if ($Miner) { $Miner.miner_type } else { $null }
            auth_mode     = if ($Miner) { $Miner.auth_mode }  else { $null }
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
# Runs inside a Start-Job process. Uses [System.Net.HttpWebRequest] instead
# of Invoke-WebRequest so that we own the response object lifetime and the
# WWW-Authenticate header is never lost to auto-disposal on 401 — which is
# the silent failure mode that Invoke-WebRequest exhibits in WPS 5.1 job
# processes when the server returns 401.
$ProbeScript = {
    param(
        [string]$Ip,
        [int]$Port,
        [int]$EndpointTimeoutMs,   # milliseconds, not seconds — passed as int
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

    # Sends one GET using HttpWebRequest. Returns the body string on success,
    # or a hashtable { StatusCode; Headers } for non-200 so the caller can
    # inspect the WWW-Authenticate header without worrying about disposal.
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

    # Step 1 — probe (expect 401 from Antminer, or 200 from open firmware)
    $probe = Invoke-RawGet -url $url -timeoutMs $EndpointTimeoutMs

    if ($probe.ok) {
        # Open firmware — no auth required
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
        return $null   # not a miner (or unreachable)
    }

    # Step 2 — digest auth using nonce from the 401 challenge
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

function Test-MinerEndpoint {
    param([string]$Ip, [int]$PreferredPort = 0)

    $ports = Get-OrderedPorts -PreferredPort $PreferredPort -Ports $MinerPorts
    # Convert EndpointTimeoutSec to ms for ProbeScript
    $timeoutMs = $EndpointTimeoutSec * 1000
    $jobs = @()
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
                        Stop-Job -Job $j -ErrorAction SilentlyContinue
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

function Discover-Miner {
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

    # Cache check
    $cached = Get-CachedDiscovery -InstallDir $InstallDir
    if ($cached -and $cached.miner_ip) {
        Write-Log "INFO" "Trying last known miner at $($cached.miner_ip):$($cached.miner_port) ..."
        $cachedMiner = Test-MinerEndpoint -Ip $cached.miner_ip -PreferredPort ([int]($cached.miner_port))
        if ($cachedMiner) {
            Write-Log "OK" "Miner still reachable - skipping scan"
            return [pscustomobject]@{ Miner = $cachedMiner; Meta = $meta }
        }
        Write-Log "WARN" "Cached miner not responding, moving on"
    }

    # Local machine check
    Write-Log "INFO" "Searching for mining machines in your network ..."
    $localMiner = Test-MinerEndpoint -Ip $ip -PreferredPort 8080
    if ($localMiner) {
        Write-Log "OK" "Miner found on local machine - $($localMiner.miner_ip):$($localMiner.miner_port)"
        return [pscustomobject]@{ Miner = $localMiner; Meta = $meta }
    }

    # Parallel TCP scan
    $allHosts = @(Get-SubnetHosts -Ip $ip -PrefixLength $prefix |
                  Where-Object { $_ -ne $ip -and $_ -ne $gateway })
    $meta.total_hosts = $allHosts.Count

    Write-Host ""
    $aliveHosts = @(Get-TcpAliveHosts -Hosts $allHosts -Ports $MinerPorts -TimeoutMs $TcpConnectTimeoutMs)
    $meta.alive_hosts = $aliveHosts.Count

    if ($aliveHosts.Count -eq 0) {
        Write-Log "WARN" "No mining machines found on this network"
        $meta.checked_hosts = 0
        return [pscustomobject]@{ Miner = $null; Meta = $meta }
    }

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

function Resolve-Miner {
    param([string]$ExplicitIp, [string]$InstallDir)

    if ($ExplicitIp) {
        Write-Log "INFO" "Manual miner IP provided: $ExplicitIp - skipping LAN scan"
        Write-Host ""

        $probed = Test-MinerEndpoint -Ip $ExplicitIp
        $meta = @{
            method        = "manual-override"
            adapter       = "manual-override"
            subnet        = "manual-override"
            total_hosts   = 0
            checked_hosts = 1
            alive_hosts   = if ($probed) { 1 } else { 0 }
        }

        if ($probed) {
            return [pscustomobject]@{ Miner = $probed; Meta = $meta }
        }

        Write-Log "WARN" "Probe to $ExplicitIp failed on standard ports - writing config anyway, agent will keep retrying"
        $manualMiner = [pscustomobject]@{
            miner_ip   = $ExplicitIp
            miner_port = 80
            miner_type = "unknown"
            auth_mode  = "unknown"
        }
        return [pscustomobject]@{ Miner = $manualMiner; Meta = $meta }
    }

    return Discover-Miner -InstallDir $InstallDir
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

    Write-Log "INFO" "Checking system requirements ..."
    $nodeCheck = Test-NodeVersion
    if (-not $nodeCheck.ok) {
        Write-Host ""
        Write-Log "ERR" "$($nodeCheck.reason). Install Node.js >= 14.17 from https://nodejs.org and re-run the installer."
        exit 1
    }
    Write-Log "OK" "Node.js $($nodeCheck.version) ready"

    $machineId = [guid]::NewGuid().ToString()

    Write-Log "INFO" "Establishing secure gateway connection ..."
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
    Write-Log "OK" "Secure gateway connected"

    # ── Register Machine ──────────────────────────────────────────────────────
    Write-Log "INFO" "Registering device with RigWorkz ..."
    try {
        $decoded      = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload))
        $installToken = ($decoded | ConvertFrom-Json).installToken
        if (-not $installToken) { throw "installToken missing from RigworkZ" }

        $registerBody = @{
            installToken = $installToken
            machineId    = $machineId
            publicKey    = $publicKeyPem
        } | ConvertTo-Json

        $registerResponse = Invoke-WebRequest `
            -Uri         "$BackendUrl/api/register" `
            -Method      POST `
            -Body        $registerBody `
            -ContentType "application/json" `
            -UseBasicParsing `
            -ErrorAction Stop

        $registerResult = $registerResponse.Content | ConvertFrom-Json
        if ($registerResult.success -ne $true) { throw "Backend rejected registration" }
        Write-Log "OK" "Machine registered"
    }
    catch {
        Write-Log "ERR" "Registration failed: $($_.Exception.Message)"
        exit 1
    }

    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor DarkCyan
    Write-Host "   RigWorkz Agent Installer" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host ""

    $result = Resolve-Miner -ExplicitIp $MinerIp -InstallDir $InstallDir
    $miner  = $result.Miner

    Write-Host ""

    if ($miner) {
        Write-Log "OK" "Mining machine found — $($miner.miner_ip) ($($miner.miner_type))"
    }
    else {
        Write-Log "WARN" "No mining machine found on this network"
        Write-Log "INFO" "Tip: if the miner is on a different subnet or reachable via Tailscale, re-run with -MinerIp <ip>"
    }

    Write-Host ""
    Write-Log "INFO" "Saving status ..."
    Save-DiscoveryResult `
        -InstallDir $InstallDir `
        -Payload    $Payload `
        -BackendUrl $BackendUrl `
        -MachineId  $machineId `
        -PublicKey  $publicKeyB64 `
        -Miner      $miner `
        -Meta       $result.Meta

    $agentDest = Join-Path $InstallDir "agent.js"
    Invoke-WebRequest -Uri $AgentUrl -OutFile $agentDest

    Write-Log "INFO" "Starting agent process ..."
    Start-Process -FilePath "node" -ArgumentList "`"$agentDest`"" -WorkingDirectory $InstallDir

    Write-Host ""
    Write-Log "OK"  "Agent is running. All done."
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Log "ERR" "Installation failed: $($_.Exception.Message)"
    exit 1
}