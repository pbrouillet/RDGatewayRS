# start-aspire.ps1
# Installs (if needed) and launches the .NET Aspire Dashboard in standalone mode.
# The dashboard receives OpenTelemetry data from the RDG Gateway via OTLP gRPC on port 4317.

param(
    [int]$DashboardPort = 18888,
    [int]$OtlpPort = 4317
)

$ErrorActionPreference = "Stop"

# Check if aspire CLI is available
$aspirePath = Get-Command aspire -ErrorAction SilentlyContinue

if (-not $aspirePath) {
    Write-Host "Aspire CLI not found. Installing..." -ForegroundColor Yellow

    # Install Aspire CLI via official install script
    & ([scriptblock]::Create((Invoke-RestMethod "https://aspire.dev/install.ps1")))

    # Refresh PATH for this session
    $userBin = Join-Path $env:USERPROFILE ".aspire\bin"
    if (Test-Path $userBin) {
        $env:PATH = "$userBin;$env:PATH"
    }

    $aspirePath = Get-Command aspire -ErrorAction SilentlyContinue
    if (-not $aspirePath) {
        Write-Error "Failed to install Aspire CLI. Please install manually: https://learn.microsoft.com/en-us/dotnet/aspire/fundamentals/setup-tooling"
        exit 1
    }

    Write-Host "Aspire CLI installed successfully." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== .NET Aspire Dashboard ===" -ForegroundColor Cyan
Write-Host "  Dashboard UI:    http://localhost:$DashboardPort" -ForegroundColor White
Write-Host "  OTLP gRPC:       http://localhost:$OtlpPort" -ForegroundColor White
Write-Host ""
Write-Host "Configure your rdg-gateway.toml:" -ForegroundColor Gray
Write-Host "  [telemetry]"
Write-Host "  otlp_endpoint = `"http://localhost:$OtlpPort`""
Write-Host "  enabled = true"
Write-Host ""
Write-Host "Starting Aspire Dashboard..." -ForegroundColor Cyan
Write-Host ""

aspire dashboard run
