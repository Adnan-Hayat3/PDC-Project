#!/bin/bash
# run_experiment.sh - Automated DDoS detection experiment runner

set -e

# Configuration
NUM_WORKERS=4
DATA_ROOT="data"
RESULTS_DIR="results"
METRICS_DIR="${RESULTS_DIR}/metrics"
PLOTS_DIR="${RESULTS_DIR}/plots"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "  DDoS Detection MPI Experiment"
echo "========================================="

# Create directories
echo -e "\n${YELLOW}[1/6]${NC} Setting up directories..."
mkdir -p ${DATA_ROOT}/partitions
mkdir -p ${METRICS_DIR}
mkdir -p ${PLOTS_DIR}

# Write CSV headers
echo "worker_rank,attack_flag,suspicious_ip,entropy,avg_rate,spike_score,total_packets,total_flows,entropy_detected,cusum_detected,ml_detected,global_attack,chosen_ip,processing_time_ms,memory_used_kb" > ${METRICS_DIR}/alerts.csv
echo "detection_latency_ms,throughput_pps,throughput_gbps,packets_processed,bytes_processed,true_positives,false_positives,true_negatives,false_negatives,cpu_usage_percent,memory_usage_kb,mpi_comm_overhead_ms" > ${METRICS_DIR}/performance.csv
echo "blocked_ip,attack_packets_blocked,legitimate_packets_blocked,blocking_efficiency,collateral_damage,block_time_ms" > ${METRICS_DIR}/blocking.csv

# Compile the detector
echo -e "\n${YELLOW}[2/6]${NC} Compiling MPI detector..."
mpicc -O3 -Wall -o ddos_detector main.c detector_enhanced.c -lm
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Compilation successful"
else
    echo -e "${RED}✗${NC} Compilation failed"
    exit 1
fi

# Preprocess datasets
echo -e "\n${YELLOW}[3/6]${NC} Preprocessing datasets..."

DATASETS=(
    "../CSV-01-12/CSV-01-12/01-12/DrDoS_UDP.csv"
    "../CSV-01-12/CSV-01-12/01-12/Syn.csv"
    "../CSV-03-11/CSV-03-11/UDP.csv"
)

for dataset in "${DATASETS[@]}"; do
    if [ -f "$dataset" ]; then
        echo "  Processing: $dataset"
        python3 scripts/preprocess_data.py "$dataset" $NUM_WORKERS $DATA_ROOT
        break  # Use first available dataset
    fi
done

# Run MPI detector
echo -e "\n${YELLOW}[4/6]${NC} Running MPI-based DDoS detector..."
echo "  Configuration: $((NUM_WORKERS + 1)) processes (1 coordinator + $NUM_WORKERS workers)"

mpirun -np $((NUM_WORKERS + 1)) ./ddos_detector $DATA_ROOT

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Detection complete"
else
    echo -e "${RED}✗${NC} Detection failed"
    exit 1
fi

# Generate analysis and plots
echo -e "\n${YELLOW}[5/6]${NC} Generating performance analysis..."
python3 scripts/analyze_results.py ${METRICS_DIR} ${PLOTS_DIR}

# Display summary
echo -e "\n${YELLOW}[6/6]${NC} Experiment Summary"
echo "========================================="

if [ -f "${METRICS_DIR}/alerts.csv" ]; then
    ALERT_COUNT=$(tail -n +2 "${METRICS_DIR}/alerts.csv" | wc -l)
    ATTACK_COUNT=$(tail -n +2 "${METRICS_DIR}/alerts.csv" | grep ",1," | wc -l)
    echo "Total alerts: $ALERT_COUNT"
    echo "Attack detections: $ATTACK_COUNT"
fi

echo ""
echo "Results saved to:"
echo "  - Alerts: ${METRICS_DIR}/alerts.csv"
echo "  - Performance: ${METRICS_DIR}/performance.csv"
echo "  - Blocking: ${METRICS_DIR}/blocking.csv"
echo "  - Plots: ${PLOTS_DIR}/"

echo ""
echo -e "${GREEN}✓ Experiment completed successfully!${NC}"
echo "========================================="
