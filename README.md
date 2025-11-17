# MPI-Based DDoS Detection System
**Scenario B: Cluster-Based Analyzer**

A high-performance distributed DDoS detection and mitigation system using MPI (Message Passing Interface) for parallel processing across multiple nodes.

---

## 📋 Project Overview

This project implements a **Complex Computing Problem (CCP)** for real-time network security analysis using parallel and distributed programming techniques. The system analyzes network traffic, detects DDoS attacks using multiple algorithms, and simulates blocking/mitigation strategies.

### Key Features

- ✅ **3 Detection Algorithms**: Entropy-based, CUSUM statistical, ML-based (logistic regression)
- ✅ **2 Blocking Methods**: Remote Triggered Black Hole (RTBH) and ACL/iptables simulation
- ✅ **Distributed Processing**: MPI-based parallelization across multiple nodes
- ✅ **Comprehensive Metrics**: Detection latency, throughput, accuracy, scalability
- ✅ **Dataset Support**: CIC-DDoS2019 (primary) and compatible formats

---

## 🏗️ System Architecture

```
┌─────────────┐
│ Coordinator │ (Rank 0)
│   Process   │ - Aggregates alerts
└──────┬──────┘ - Makes global decisions
       │        - Triggers blocking
       │
       ├────────┬────────┬────────┐
       │        │        │        │
   ┌───▼───┐┌──▼───┐┌──▼───┐┌──▼───┐
   │Worker1││Worker2││Worker3││Worker4│
   │(Rank1)││(Rank2)││(Rank3)││(Rank4)│
   └───────┘└──────┘└──────┘└──────┘
       │        │        │        │
   ┌───▼────────▼────────▼────────▼───┐
   │    Partitioned Dataset           │
   │    (Hash/Time-based split)       │
   └──────────────────────────────────┘
```

### Detection Pipeline

1. **Data Partitioning**: Traffic flows divided among MPI workers
2. **Local Analysis**: Each worker:
   - Builds IP statistics
   - Computes features (entropy, rate, spike score)
   - Runs 3 detection algorithms
   - Generates local alert
3. **Alert Aggregation**: Coordinator collects alerts from all workers
4. **Global Decision**: Voting mechanism (≥2 workers) confirms attack
5. **Blocking**: RTBH + ACL rules applied to malicious IPs

---

## 🛠️ Requirements

### Software Dependencies

- **C Compiler**: GCC, Clang, or MSVC with C99 support
- **MPI Implementation**:
  - Linux: MPICH or OpenMPI
    ```bash
    sudo apt-get install mpich libmpich-dev
    ```
  - Windows: MS-MPI
    - Download: [MS-MPI SDK](https://docs.microsoft.com/en-us/message-passing-interface/microsoft-mpi)
- **Python 3.7+** (for analysis tools):
  ```bash
  pip install pandas matplotlib numpy
  ```

### Hardware Requirements

- Minimum: 4 CPU cores (1 coordinator + 3 workers)
- Recommended: 8+ cores for scalability testing
- Memory: 4GB+ RAM

---

## 📦 Dataset Preparation

### Using CIC-DDoS2019 Dataset

1. **Download**: [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html)

2. **Convert to Compatible Format**:
   ```bash
   # Build the CSV parser
   make csv_parser
   
   # Partition dataset for N workers
   ./csv_parser path/to/DrDoS_UDP.csv data/partitions 4
   ```

3. **Expected Output**:
   ```
   data/partitions/
   ├── part_1.csv
   ├── part_2.csv
   ├── part_3.csv
   └── part_4.csv
   ```

### CSV Format

Each partition file contains:
```csv
src_ip,dst_ip,bytes,timestamp,protocol,src_port,dst_port,packets
172.16.0.5,192.168.50.1,802,1543665417,17,60954,29816,2
```

---

## 🚀 Build and Run

### Quick Start (Linux/WSL)

```bash
# 1. Build everything
make all

# 2. Setup directories
make setup

# 3. Preprocess dataset
./csv_parser ../CSV-01-12/CSV-01-12/01-12/DrDoS_UDP.csv data/partitions 4

# 4. Run with 4 MPI processes (1 coordinator + 3 workers)
make run-4

# Or use the automated script
./run.sh 4 ../CSV-01-12/CSV-01-12/01-12/DrDoS_UDP.csv
```

### Quick Start (Windows PowerShell)

```powershell
# Build and run
.\run.ps1 -NumWorkers 4 -Dataset "..\CSV-01-12\CSV-01-12\01-12\DrDoS_UDP.csv"
```

### Manual Build

```bash
# Compile detector
mpicc -Wall -O2 -std=c99 -c main.c detector.c
mpicc -o ddos_detector main.o detector.o -lm

# Compile CSV parser
mpicc -Wall -O2 -std=c99 -o csv_parser csv_parser.c -lm
```

### Running with Different Configurations

```bash
# Test with 2 processes
mpiexec -n 2 ./ddos_detector data

# Production with 8 processes
mpiexec -n 8 ./ddos_detector data

# Using hostfile for cluster deployment
mpiexec -hostfile hosts.txt -n 8 ./ddos_detector data
```

---

## 📊 Analysis and Visualization

### Generate Analysis Report

```bash
python analyze_results.py
```

### Output Files

```
results/
├── metrics/
│   ├── alerts.csv          # Detection alerts from workers
│   ├── blocking.csv        # Blocking effectiveness stats
│   └── iptables_rules.txt  # Generated firewall rules
├── plots/
│   ├── detection_methods.png    # Algorithm comparison
│   ├── performance_metrics.png  # Worker performance
│   ├── feature_analysis.png     # Attack vs normal features
│   └── blocking_efficiency.png  # Blocking effectiveness
└── analysis_report.txt     # Comprehensive text report
```

---

## 🔬 Detection Algorithms

### 1. Entropy-Based Detection
- **Principle**: Measures randomness in source IP distribution
- **Threshold**: Entropy < 1.0 indicates concentrated traffic (DDoS)
- **Use Case**: Detects attacks with few source IPs

### 2. CUSUM Statistical Detection
- **Principle**: Cumulative Sum control chart for anomaly detection
- **Method**: Tracks deviations from baseline packet rate
- **Threshold**: CUSUM > 5.0 standard deviations
- **Use Case**: Detects gradual rate increases

### 3. ML-Based Detection (Logistic Regression)
- **Features**: Entropy, avg_rate, spike_score, unique_ips
- **Model**: Weighted sum with sigmoid activation
- **Threshold**: Probability > 0.6 classifies as attack
- **Use Case**: Combined feature analysis

### Voting Mechanism
Attack confirmed if **≥2 out of 3** algorithms detect anomaly.

---

## 🛡️ Blocking/Mitigation Methods

### 1. Remote Triggered Black Hole (RTBH)
```c
[RTBH] Blackholing traffic to/from IP: 192.168.50.1
```
- Simulates BGP-based traffic redirection
- Efficiency: ~95% attack traffic blocked
- Collateral: ~1% legitimate traffic affected

### 2. Access Control List (ACL/iptables)
```bash
iptables -A INPUT -s 192.168.50.1 -j DROP
iptables -A OUTPUT -d 192.168.50.1 -j DROP
```
- Generates firewall rules
- Applied at network edge
- Logged to `results/metrics/iptables_rules.txt`

---

## 📈 Performance Metrics

### Detection Metrics
- **Detection Latency**: Time from attack start to first alert
- **True Positive Rate (TPR)**: Correctly detected attacks
- **False Positive Rate (FPR)**: Legitimate traffic flagged
- **Precision, Recall, F1-Score**: Classification quality

### Throughput Metrics
- **Packets/Second**: Processing capacity
- **Gbps**: Effective bandwidth analyzed
- **Processing Time**: Per-worker computation time

### Scalability Metrics
- **Speedup**: Performance vs. number of workers
- **Efficiency**: Utilization of parallel resources
- **Load Balance**: Work distribution across workers

### Resource Metrics
- **CPU Usage**: Per-worker processor utilization
- **Memory Usage**: Memory footprint per worker
- **MPI Communication Overhead**: Inter-process messaging cost

---

## 🧪 Testing and Validation

### Unit Testing
```bash
# Test with small dataset
make test
```

### Scalability Testing
```bash
# Test with different worker counts
for n in 2 4 6 8; do
    echo "Testing with $n processes..."
    mpiexec -n $n ./ddos_detector data
done
```

### Performance Profiling
```bash
# Use MPI profiling tools
mpiexec -n 4 -profile=profiler ./ddos_detector data
```

---

## 📁 Project Structure

```
PDC-Project/
├── main.c                  # Entry point
├── detector.c              # Core detection logic
├── detector.h              # Header definitions
├── csv_parser.c            # Dataset preprocessing
├── Makefile                # Build configuration
├── run.sh                  # Linux run script
├── run.ps1                 # Windows run script
├── analyze_results.py      # Analysis/visualization
├── README.md               # This file
├── data/
│   └── partitions/         # Partitioned datasets
└── results/
    ├── metrics/            # Performance data
    └── plots/              # Visualizations
```

---

## 🎓 Complex Computing Problem (CCP) Justification

### Why This Qualifies as CCP

1. **No Deterministic Solution**: DDoS detection requires heuristics and ML
2. **Multiple Interacting Components**: Data ingestion, detection, blocking, evaluation
3. **Real-World Complexity**: Large-scale datasets, high-speed traffic
4. **Trade-offs**: Accuracy vs. speed, detection latency vs. resource usage
5. **Research-Based Decisions**: Algorithm selection, partitioning strategy, threshold tuning

### OBE Alignment
- **PLO 3**: Problem analysis in complex security domain
- **PLO 4**: Design/development of distributed solution
- **NCEAC Criteria**: Advanced computing knowledge, specialized techniques

---

## 📚 References

### Datasets
- [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html)
- [CAIDA DDoS 2007](https://www.caida.org/data/passive/ddos-20070804_dataset.xml)

### Detection Algorithms
- Entropy-based: [Shannon Entropy for Network Anomaly Detection]
- CUSUM: [Page's Cumulative Sum for Change Detection]
- ML-based: [Machine Learning for DDoS Detection (Survey)]

### Tools & Libraries
- [MPI Standard](https://www.mpi-forum.org/)
- [MS-MPI Documentation](https://docs.microsoft.com/en-us/message-passing-interface/microsoft-mpi)

---

## 🐛 Troubleshooting

### Common Issues

**1. MPI not found**
```bash
# Linux
sudo apt-get install mpich libmpich-dev

# Windows: Install MS-MPI SDK
```

**2. Partition files missing**
```bash
# Regenerate partitions
./csv_parser <dataset.csv> data/partitions <num_workers>
```

**3. Python modules missing**
```bash
pip install pandas matplotlib numpy
```

**4. Compilation errors**
```bash
# Ensure C99 support
mpicc --version
```

---

## 👥 Contributors

- **Adnan Hayat** - Project Developer

---

## 📄 License

This project is developed for educational purposes as part of the PDC (Parallel and Distributed Computing) course.

---

## 📞 Contact

For questions or issues, please open an issue on the GitHub repository.

---

**Last Updated**: November 2025
