# start-guacd-podman.ps1
# Launches the Apache Guacamole daemon (guacd) using Podman.
# guacd handles RDP/VNC/SSH connections on behalf of the gateway.

param(
    [int]$GuacdPort = 4822,
    [string]$ImageTag = "1.5.5"
)

$ErrorActionPreference = "Stop"

$containerName = "rdg-guacd"

# Check if Podman is available
$podman = Get-Command podman -ErrorAction SilentlyContinue
if (-not $podman) {
    Write-Error "Podman is not installed or not in PATH."
    exit 1
}

# Stop existing container if running
$existing = podman ps -aq --filter "name=$containerName" 2>$null
if ($existing) {
    Write-Host "Stopping existing guacd container..." -ForegroundColor Yellow
    podman rm -f $containerName | Out-Null
}

Write-Host ""
Write-Host "=== Apache Guacamole Daemon (guacd) ===" -ForegroundColor Cyan
Write-Host "  Listening on:  localhost:$GuacdPort" -ForegroundColor White
Write-Host "  Image:         guacamole/guacd:$ImageTag" -ForegroundColor White
Write-Host ""
Write-Host "Configure your rdg-gateway.toml:" -ForegroundColor Gray
Write-Host "  [guacamole]"
Write-Host "  enabled = true"
Write-Host "  guacd_host = `"localhost`""
Write-Host "  guacd_port = $GuacdPort"
Write-Host ""
Write-Host "Starting guacd..." -ForegroundColor Cyan
Write-Host ""

podman run -d --rm `
    --name $containerName `
    -p "${GuacdPort}:4822" `
    "guacamole/guacd:$ImageTag"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "guacd is running. Container: $containerName" -ForegroundColor Green
    Write-Host "Stop with: podman stop $containerName" -ForegroundColor Gray
} else {
    Write-Error "Failed to start guacd container."
}
