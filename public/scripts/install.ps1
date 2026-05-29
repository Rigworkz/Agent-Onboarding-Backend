param(
    [string]$sid
)

# fallback if param not bound
if (-not $sid -and $args.Count -gt 0) {
    $sid = $args[0]
}

$backend = "http://35.224.207.37:5000"
$tempFile = "$env:TEMP\rw.ps1"

if (-not $sid) {
    Write-Host "Missing session id" -ForegroundColor Red
    exit 1
}

Write-Host "Fetching install token..." -ForegroundColor Cyan

try {
    $encodedSid = [System.Web.HttpUtility]::UrlEncode($sid)
$res = Invoke-RestMethod -Uri "$backend/api/install/bootstrap?sid=$encodedSid"
} catch {
    Write-Host "Failed to fetch token: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if (-not $res.installToken) {
    Write-Host "Invalid bootstrap response" -ForegroundColor Red
    exit 1
}

$payload = [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes(
        "{""installToken"":""$($res.installToken)""}"
    )
)

if (-not (Test-Path $tempFile)) {
    Write-Host "Installer download failed" -ForegroundColor Red
    exit 1
}

Write-Host "Downloading installer..." -ForegroundColor Cyan

Invoke-WebRequest `
    -Uri "$backend/scripts/rigworkz-install.ps1" `
    -OutFile $tempFile

Write-Host "Running installer..." -ForegroundColor Cyan

& $tempFile -Payload $payload -BackendUrl $backend