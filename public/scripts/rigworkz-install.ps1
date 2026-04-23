param(
    [string]$Payload,
    [string]$BackendUrl = "http://35.224.207.37:5000",
    [string]$AgentUrl = "http://35.224.207.37:5000/scripts/agent.js",
    [string]$MockTelemetryUrl = "http://35.224.207.37:5000/scripts/mock-telemetry.json",
    [string]$InstallDir = "C:\rigworkz-agent",
    [int]$PingTimeoutMs = 250,
    [int]$EndpointTimeoutSec = 1
)

if (-not $Payload) {
    Write-Host "No payload provided"
    exit 1
}

# ─────────────────────────────────────────────
# NETWORK HELPERS (NO UINT BUGS)
# ─────────────────────────────────────────────

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

        if ($bits -ge 8) { $mask[$i] = 255 }
        elseif ($bits -le 0) { $mask[$i] = 0 }
        else { $mask[$i] = [byte](256 - [math]::Pow(2, 8 - $bits)) }
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

    $networkInt = Convert-BytesToUInt32 $networkBytes
    $wildcardInt = Convert-BytesToUInt32 $wildcardBytes

    $start = [uint64]$networkInt + 1
    $end = [uint64]$networkInt + [uint64]$wildcardInt - 1

    $hosts = @()
    for ($n = $start; $n -le $end; $n++) {
        $hosts += Convert-UInt32ToIp ([uint32]$n)
    }

    return $hosts
}

function Test-HostAlive {
    param([string]$Ip)

    ping.exe -n 1 -w $PingTimeoutMs $Ip *> $null
    return $LASTEXITCODE -eq 0
}

function Test-MinerEndpoint {
    param([string]$Ip)

    foreach ($port in @(80, 8080)) {
        try {
            $url = "http://$Ip`:$port/cgi-bin/stats.cgi"
            $res = Invoke-WebRequest -Uri $url -TimeoutSec $EndpointTimeoutSec -UseBasicParsing

            if ($res.StatusCode -eq 200) {
                $json = $res.Content | ConvertFrom-Json

                if ($json.INFO.type -and $json.STATS[0]) {
                    return @{
                        miner_ip   = $Ip
                        miner_port = $port
                        miner_type = $json.INFO.type
                    }
                }
            }
        } catch {}
    }

    return $null
}

function Discover-Miner {
    $cfg = Get-PrimaryIPv4Config
    $ip = $cfg.IPv4Address.IPAddress
    $prefix = $cfg.IPv4Address.PrefixLength

    Write-Host "Scanning subnet: $ip/$prefix"

    $hosts = Get-SubnetHosts -Ip $ip -PrefixLength $prefix

    foreach ($host in $hosts) {
        if (Test-HostAlive $host) {
            Write-Host "Alive: $host"

            $miner = Test-MinerEndpoint $host
            if ($miner) {
                Write-Host "Miner found: $($miner.miner_ip):$($miner.miner_port)"
                return $miner
            }
        }
    }

    return $null
}

# ─────────────────────────────────────────────
# INSTALL FLOW
# ─────────────────────────────────────────────

try {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $machineId = [guid]::NewGuid().ToString()

    Write-Host "Starting network scan..."
    $miner = Discover-Miner

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        machine_id = $machineId
        miner_ip   = if ($miner) { $miner.miner_ip } else { $null }
        miner_port = if ($miner) { $miner.miner_port } else { $null }
    } | ConvertTo-Json -Depth 5

    $configPath = Join-Path $InstallDir "config.json"
    Set-Content -Path $configPath -Value $config -Encoding Ascii

    $agentDest = Join-Path $InstallDir "agent.js"
    Invoke-WebRequest -Uri $AgentUrl -OutFile $agentDest

    $mockDest = Join-Path $InstallDir "mock-telemetry.json"
    Invoke-WebRequest -Uri $MockTelemetryUrl -OutFile $mockDest

    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Write-Host "Node.js not found"
        exit 1
    }

    Write-Host "Starting agent..."
    Start-Process -FilePath "node" -ArgumentList "`"$agentDest`"" -WorkingDirectory $InstallDir -NoNewWindow
}
catch {
    Write-Host "Installation failed: $($_.Exception.Message)"
    exit 1
}