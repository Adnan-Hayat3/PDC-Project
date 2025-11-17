# PowerShell script for Windows - run_experiment.ps1
# Automated DDoS detection experiment runner

param(
    [int]$NumWorkers = 4,
    [string]$DataRoot = "data",
    [string]$ResultsDir = "results"
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  DDoS Detection MPI Experiment" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$MetricsDir = Join-Path $ResultsDir "metrics"
$PlotsDir = Join-Path $ResultsDir "plots"

# Create directories
Write-Host "`n[1/6] Setting up directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path (Join-Path $DataRoot "partitions") | Out-Null
New-Item -ItemType Directory -Force -Path $MetricsDir | Out-Null
New-Item -ItemType Directory -Force -Path $PlotsDir | Out-Null

# Write CSV headers
"worker_rank,attack_flag,suspicious_ip,entropy,avg_rate,spike_score,total_packets,total_flows,entropy_detected,cusum_detected,ml_detected,global_attack,chosen_ip,processing_time_ms,memory_used_kb" | Out-File -FilePath (Join-Path $MetricsDir "alerts.csv") -Encoding UTF8
"detection_latency_ms,throughput_pps,throughput_gbps,packets_processed,bytes_processed,true_positives,false_positives,true_negatives,false_negatives,cpu_usage_percent,memory_usage_kb,mpi_comm_overhead_ms" | Out-File -FilePath (Join-Path $MetricsDir "performance.csv") -Encoding UTF8
"blocked_ip,attack_packets_blocked,legitimate_packets_blocked,blocking_efficiency,collateral_damage,block_time_ms" | Out-File -FilePath (Join-Path $MetricsDir "blocking.csv") -Encoding UTF8

# Compile the detector
Write-Host "`n[2/6] Compiling MPI detector..." -ForegroundColor Yellow
mpicc -O3 -Wall -o ddos_detector.exe main.c detector_enhanced.c -lm

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Compilation successful" -ForegroundColor Green
} else {
    Write-Host "✗ Compilation failed" -ForegroundColor Red
    exit 1
}

# Preprocess datasets
Write-Host "`n[3/6] Preprocessing datasets..." -ForegroundColor Yellow

$Datasets = @(
    "..\CSV-01-12\CSV-01-12\01-12\DrDoS_UDP.csv",
    "..\CSV-01-12\CSV-01-12\01-12\Syn.csv",
    "..\CSV-03-11\CSV-03-11\UDP.csv"
)

foreach ($dataset in $Datasets) {
    if (Test-Path $dataset) {
        Write-Host "  Processing: $dataset"
        python scripts\preprocess_data.py $dataset $NumWorkers $DataRoot
        break
    }
}

# Run MPI detector
Write-Host "`n[4/6] Running MPI-based DDoS detector..." -ForegroundColor Yellow
Write-Host "  Configuration: $($NumWorkers + 1) processes (1 coordinator + $NumWorkers workers)"

mpiexec -n ($NumWorkers + 1) .\ddos_detector.exe $DataRoot

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Detection complete" -ForegroundColor Green
} else {
    Write-Host "✗ Detection failed" -ForegroundColor Red
    exit 1
}

# Generate analysis and plots
Write-Host "`n[5/6] Generating performance analysis..." -ForegroundColor Yellow
python scripts\analyze_results.py $MetricsDir $PlotsDir

# Display summary
Write-Host "`n[6/6] Experiment Summary" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

$AlertsFile = Join-Path $MetricsDir "alerts.csv"
if (Test-Path $AlertsFile) {
    $AlertCount = (Get-Content $AlertsFile | Measure-Object -Line).Lines - 1
    $AttackCount = (Get-Content $AlertsFile | Select-String ",1,").Count
    Write-Host "Total alerts: $AlertCount"
    Write-Host "Attack detections: $AttackCount"
}

Write-Host ""
Write-Host "Results saved to:"
Write-Host "  - Alerts: $MetricsDir\alerts.csv"
Write-Host "  - Performance: $MetricsDir\performance.csv"
Write-Host "  - Blocking: $MetricsDir\blocking.csv"
Write-Host "  - Plots: $PlotsDir\"

Write-Host ""
Write-Host "✓ Experiment completed successfully!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
