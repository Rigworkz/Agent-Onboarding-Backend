param(
    [string]$Payload,
    [string]$BackendUrl = "http://35.224.207.37:5000",
    [string]$AgentUrl = "http://35.224.207.37:5000/scripts/agent.js",
    [string]$MockTelemetryUrl = "http://35.224.207.37:5000/scripts/mock-telemetry.json",
    [string]$InstallDir = "C:\rigworkz-agent"
)

if (-not $Payload) {
    Write-Host "No payload provided"
    exit 1
}

try {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $machineId = [guid]::NewGuid().ToString()

    $config = @{
        payload    = $Payload
        backendUrl = $BackendUrl
        machine_id = $machineId
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