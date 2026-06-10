# start-guacd.ps1
# Launches the Apache Guacamole daemon (guacd) using Docker.
# guacd handles RDP/VNC/SSH connections on behalf of the gateway.

param(
    [int]$GuacdPort = 4822,
    [string]$ImageTag = "1.5.5"
)

$ErrorActionPreference = "Stop"

$containerName = "rdg-guacd"

# Check if Docker is available
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Error "Docker is not installed or not in PATH. Please install Docker Desktop."
    exit 1
}

# Stop existing container if running
$existing = docker ps -aq --filter "name=$containerName" 2>$null
if ($existing) {
    Write-Host "Stopping existing guacd container..." -ForegroundColor Yellow
    docker rm -f $containerName | Out-Null
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

docker run --rm `
    --name $containerName `
    -p "${GuacdPort}:4822" `
    "guacamole/guacd:$ImageTag"
