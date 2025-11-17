#!/bin/bash
# Build and run script for DDoS Detection System (Linux/WSL)

set -e

echo "========================================"
echo "MPI-Based DDoS Detection System"
echo "Scenario B: Cluster-Based Analyzer"
echo "========================================"

# Configuration
NUM_WORKERS=${1:-4}
DATASET=${2:-"../CSV-01-12/CSV-01-12/01-12/DrDoS_UDP.csv"}

echo ""
echo "Configuration:"
echo "  Workers: $NUM_WORKERS"
echo "  Dataset: $DATASET"
echo ""

# Step 1: Create directories
echo "[1/5] Creating directory structure..."
mkdir -p data/partitions
mkdir -p results/metrics
mkdir -p results/plots
echo "  ✓ Directories created"

# Step 2: Build executables
echo ""
echo "[2/5] Building executables..."
make clean
make all
echo "  ✓ Build complete"

# Step 3: Preprocess dataset
echo ""
echo "[3/5] Preprocessing dataset..."
if [ -f "$DATASET" ]; then
    ./csv_parser "$DATASET" data/partitions $NUM_WORKERS
    echo "  ✓ Dataset partitioned"
else
    echo "  ⚠ Dataset not found: $DATASET"
    echo "  Using existing partitions if available..."
fi

# Step 4: Create CSV headers
echo ""
echo "[4/5] Initializing result files..."
echo "worker_rank,attack_flag,suspicious_ip,entropy,avg_rate,spike_score,total_packets,total_flows,entropy_detected,cusum_detected,ml_detected,processing_time_ms,memory_used_kb,global_attack,chosen_ip" > results/metrics/alerts.csv
echo "blocked_ip,attack_packets_blocked,legitimate_packets_blocked,blocking_efficiency,collateral_damage,block_time_ms" > results/metrics/blocking.csv
echo "" > results/metrics/iptables_rules.txt
echo "  ✓ Result files initialized"

# Step 5: Run MPI application
echo ""
echo "[5/5] Running MPI DDoS detector..."
echo "  Command: mpiexec -n $((NUM_WORKERS + 1)) ./ddos_detector data"
echo ""

mpiexec -n $((NUM_WORKERS + 1)) ./ddos_detector data

echo ""
echo "========================================"
echo "Execution complete!"
echo "Results saved to: results/metrics/"
echo "========================================"
echo ""
echo "View results:"
echo "  cat results/metrics/alerts.csv"
echo "  cat results/metrics/blocking.csv"
echo "  cat results/metrics/iptables_rules.txt"
echo ""
