<#
.SYNOPSIS
    Local PowerShell orchestrator for LLM Security Guardrails Proxy.
.EXAMPLE
    .\scripts\run_local.ps1 -Test
    .\scripts\run_local.ps1 -Benchmark
    .\scripts\run_local.ps1 -Run
#>

param (
    [switch]$Install,
    [switch]$Run,
    [switch]$Test,
    [switch]$Benchmark,
    [switch]$Report,
    [switch]$Docker
)

$ErrorActionPreference = "Stop"

if ($Install) {
    Write-Host "[*] Installing dependencies..." -ForegroundColor Cyan
    python -m pip install --upgrade pip
    pip install ".[dev]"
}
elseif ($Run) {
    Write-Host "[*] Starting LLM Security Guardrails Proxy on :8080..." -ForegroundColor Green
    python -m uvicorn proxy.main:app --host 0.0.0.0 --port 8080 --reload
}
elseif ($Test) {
    Write-Host "[*] Running pytest test suite..." -ForegroundColor Cyan
    python -m pytest -v tests/
}
elseif ($Benchmark) {
    Write-Host "[*] Executing automated adversarial red-teaming benchmark..." -ForegroundColor Yellow
    python red_teaming/evaluate_benchmark.py
}
elseif ($Report) {
    Write-Host "[*] Generating HTML & Markdown compliance audit reports..." -ForegroundColor Magenta
    python red_teaming/export_report.py
}
elseif ($Docker) {
    Write-Host "[*] Launching Docker Compose stack..." -ForegroundColor Green
    docker compose -f docker/docker-compose.yml up -d --build
}
else {
    Write-Host "Usage: .\scripts\run_local.ps1 [-Install | -Run | -Test | -Benchmark | -Report | -Docker]" -ForegroundColor Yellow
}
