param(
    [string]$Payload,
    [string]$BackendUrl = "http://35.224.207.37:5000",
    [string]$AgentUrl = "http://35.224.207.37:5000/scripts/agent.js",
    [string]$MockTelemetryUrl = "http://35.224.207.37:5000/scripts/mock-telemetry.json",
    [string]$InstallDir = "C:\rigworkz-agent",
    [int]$BatchSize = 32,
    [int]$PingTimeoutMs = 250,
    [int]$EndpointTimeoutSec = 1
)

if (-not $Payload) {
    Write-Host "No payload provided"
    exit 1
}

function ConvertTo-UInt32Ip {
    param([string]$Ip)
    $bytes = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-UInt32Ip {
    param([uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
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
        throw "No active IPv4 adapter with default gateway found"
    }

    return $cfg
}

function Get-SubnetHosts {
    param(
        [string]$Ip,
        [string]$Mask
    )

    $ipInt = ConvertTo-UInt32Ip -Ip $Ip
    $maskInt = ConvertTo-UInt32Ip -Ip $Mask

    $network = $ipInt -band $maskInt
    $wildcard = [uint32]([uint32]0xFFFFFFFF -bxor $maskInt)
    $broadcast = $network -bor $wildcard

    $start = [uint32]($network + 1)
    $end = [uint32]($broadcast - 1)

    $hosts = New-Object System.Collections.Generic.List[string]
    for ($i = $start; $i -le $end; $i++) {
        $hosts.Add((ConvertFrom-UInt32Ip -Value $i))
    }

    return $hosts
}

function Test-HostAlive {
    param([string]$Ip)

    ping.exe -n 1 -w $PingTimeoutMs $Ip *> $null
    return $LASTEXITCODE -eq 0
}

function Test-MinerEndpoint {
    param(
        [string]$Ip,
        [int[]]$Ports = @(80, 8080)
    )

    foreach ($port in $Ports) {
        try {
            $url = "http://$Ip`:$port/cgi-bin/stats.cgi"
            $res = Invoke-WebRequest -Uri $url -TimeoutSec $EndpointTimeoutSec -UseBasicParsing

            if ($res.StatusCode -eq 200) {
                $json = $res.Content | ConvertFrom-Json

                if ($json.INFO.type -and $json.STATS[0]) {
                    return [pscustomobject]@{
                        miner_ip   = $Ip
                        miner_port = $port
                        miner_type = $json.INFO.type
                    }
                }
            }
        } catch {
            # try next port
        }
    }

    return $null
}

function Invoke-ParallelPingBatch {
    param([string[]]$Ips)

    $jobs = @()

    foreach ($ip in $Ips) {
        $jobs += Start-Job -ArgumentList $ip, $PingTimeoutMs -ScriptBlock {
            param($TargetIp, $TimeoutMs)
            ping.exe -n 1 -w $TimeoutMs $TargetIp *> $null
            if ($LASTEXITCODE -eq 0) {
                return $TargetIp
            }
        }
    }

    $alive = @()
    if ($jobs.Count -gt 0) {
        $results = Receive-Job -Job $jobs -Wait -AutoRemoveJob
        foreach ($r in $results) {
            if ($r) { $alive += $r }
        }
    }

    return $alive
}

function Discover-Miner {
    $cfg = Get-PrimaryIPv4Config
    $ip = $cfg.IPv4Address.IPAddress
    $mask = $cfg.IPv4Address.PrefixLength

    $subnetMask = switch ($mask) {
        8   { "255.0.0.0" }
        9   { "255.128.0.0" }
        10  { "255.192.0.0" }
        11  { "255.224.0.0" }
        12  { "255.240.0.0" }
        13  { "255.248.0.0" }
        14  { "255.252.0.0" }
        15  { "255.254.0.0" }
        16  { "255.255.0.0" }
        17  { "255.255.128.0" }
        18  { "255.255.192.0" }
        19  { "255.255.224.0" }
        20  { "255.255.240.0" }
        21  { "255.255.248.0" }
        22  { "255.255.252.0" }
        23  { "255.255.254.0" }
        24  { "255.255.255.0" }
        25  { "255.255.255.128" }
        26  { "255.255.255.192" }
        27  { "255.255.255.224" }
        28  { "255.255.255.240" }
        29  { "255.255.255.248" }
        30  { "255.255.255.252" }
        default { throw "Unsupported subnet prefix length: $mask" }
    }

    $hosts = Get-SubnetHosts -Ip $ip -Mask $subnetMask
    Write-Host "Scanning subnet from adapter $($cfg.InterfaceAlias): $ip/$mask"

    for ($offset = 0; $offset -lt $hosts.Count; $offset += $BatchSize) {
        $end = [Math]::Min($offset + $BatchSize - 1, $hosts.Count - 1)
        $batch = $hosts[$offset..$end]
        $aliveHosts = Invoke-ParallelPingBatch -Ips $batch

        foreach ($aliveIp in $aliveHosts) {
            Write-Host "Alive host found: $aliveIp"

            $miner = Test-MinerEndpoint -Ip $aliveIp -Ports @(80, 8080)
            if ($miner) {
                Write-Host "Miner confirmed at $($miner.miner_ip):$($miner.miner_port)"
                return $miner
            }
        }
    }

    return $null
}

try {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $machineId = [guid]::NewGuid().ToString()
    $miner = Discover-Miner

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        machine_id = $machineId
        miner_ip   = if ($miner) { $miner.miner_ip } else { $null }
        miner_port = if ($miner) { $miner.miner_port } else { $null }
        discovery  = @{
            method     = "ping+http"
            status     = if ($miner) { "found" } else { "not_found" }
            scanned_at = (Get-Date).ToString("o")
            miner_type = if ($miner) { $miner.miner_type } else { $null }
        }
    } | ConvertTo-Json -Depth 5

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