# PowerShell build and run script for Windows
# MPI-Based DDoS Detection System

param(
    [int]$NumWorkers = 4,
    [string]$Dataset = "..\CSV-01-12\CSV-01-12\01-12\DrDoS_UDP.csv"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "MPI-Based DDoS Detection System" -ForegroundColor Cyan
Write-Host "Scenario B: Cluster-Based Analyzer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Workers: $NumWorkers"
Write-Host "  Dataset: $Dataset"
Write-Host ""

# Step 1: Create directories
Write-Host "[1/5] Creating directory structure..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "data\partitions" | Out-Null
New-Item -ItemType Directory -Force -Path "results\metrics" | Out-Null
New-Item -ItemType Directory -Force -Path "results\plots" | Out-Null
Write-Host "  ✓ Directories created" -ForegroundColor Green

# Step 2: Build executables (requires MS-MPI and compiler)
Write-Host ""
Write-Host "[2/5] Building executables..." -ForegroundColor Green
Write-Host "  Note: Ensure mpicc (from MS-MPI SDK or MinGW-w64) is in PATH" -ForegroundColor Yellow

# Check if make is available
$makeAvailable = Get-Command make -ErrorAction SilentlyContinue
if ($makeAvailable) {
    make clean
    make all
    Write-Host "  ✓ Build complete" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Make not found. Build manually with:" -ForegroundColor Yellow
    Write-Host "    mpicc -Wall -O2 -std=c99 -c main.c detector.c" -ForegroundColor Gray
    Write-Host "    mpicc -o ddos_detector main.o detector.o -lm" -ForegroundColor Gray
    Write-Host "    mpicc -Wall -O2 -std=c99 -o csv_parser csv_parser.c -lm" -ForegroundColor Gray
}

# Step 3: Preprocess dataset
Write-Host ""
Write-Host "[3/5] Preprocessing dataset..." -ForegroundColor Green
if (Test-Path $Dataset) {
    .\csv_parser.exe $Dataset "data\partitions" $NumWorkers
    Write-Host "  ✓ Dataset partitioned" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Dataset not found: $Dataset" -ForegroundColor Yellow
    Write-Host "  Using existing partitions if available..." -ForegroundColor Yellow
}

# Step 4: Create CSV headers
Write-Host ""
Write-Host "[4/5] Initializing result files..." -ForegroundColor Green
"worker_rank,attack_flag,suspicious_ip,entropy,avg_rate,spike_score,total_packets,total_flows,entropy_detected,cusum_detected,ml_detected,processing_time_ms,memory_used_kb,global_attack,chosen_ip" | Out-File -FilePath "results\metrics\alerts.csv" -Encoding ASCII
"blocked_ip,attack_packets_blocked,legitimate_packets_blocked,blocking_efficiency,collateral_damage,block_time_ms" | Out-File -FilePath "results\metrics\blocking.csv" -Encoding ASCII
"" | Out-File -FilePath "results\metrics\iptables_rules.txt" -Encoding ASCII
Write-Host "  ✓ Result files initialized" -ForegroundColor Green

# Step 5: Run MPI application
Write-Host ""
Write-Host "[5/5] Running MPI DDoS detector..." -ForegroundColor Green
$TotalProcs = $NumWorkers + 1
Write-Host "  Command: mpiexec -n $TotalProcs .\ddos_detector.exe data" -ForegroundColor Gray
Write-Host ""

mpiexec -n $TotalProcs .\ddos_detector.exe data

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Execution complete!" -ForegroundColor Green
Write-Host "Results saved to: results\metrics\" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "View results:" -ForegroundColor Yellow
Write-Host "  Get-Content results\metrics\alerts.csv" -ForegroundColor Gray
Write-Host "  Get-Content results\metrics\blocking.csv" -ForegroundColor Gray
Write-Host "  Get-Content results\metrics\iptables_rules.txt" -ForegroundColor Gray
Write-Host ""
