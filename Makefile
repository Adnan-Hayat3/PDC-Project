# Makefile for MPI-based DDoS Detection System
# Scenario B: Cluster-Based Analyzer

CC = mpicc
CFLAGS = -Wall -O2 -std=c99
LDFLAGS = -lm

# Targets
TARGETS = ddos_detector csv_parser

# Source files
DETECTOR_SRCS = main.c detector.c
DETECTOR_OBJS = $(DETECTOR_SRCS:.c=.o)

PARSER_SRCS = csv_parser.c
PARSER_OBJS = $(PARSER_SRCS:.c=.o)

# Default target
all: $(TARGETS)

# Build main DDoS detector
ddos_detector: $(DETECTOR_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built ddos_detector successfully"

# Build CSV parser/preprocessor
csv_parser: $(PARSER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built csv_parser successfully"

# Compile object files
%.o: %.c detector.h
	$(CC) $(CFLAGS) -c $< -o $@

# Create required directories
setup:
	@echo "Creating directory structure..."
	@mkdir -p data/partitions
	@mkdir -p results/metrics
	@mkdir -p results/plots
	@echo "Directory structure created"

# Clean build artifacts
clean:
	rm -f $(TARGETS) *.o
	@echo "Cleaned build artifacts"

# Clean all including results
distclean: clean
	rm -rf data/partitions/* results/metrics/* results/plots/*
	@echo "Cleaned all generated files"

# Preprocess dataset (example)
preprocess: csv_parser setup
	@echo "Preprocessing dataset..."
	@echo "Usage: ./csv_parser <input_csv> data/partitions <num_workers>"
	@echo "Example: ./csv_parser ../CSV-01-12/CSV-01-12/01-12/DrDoS_UDP.csv data/partitions 4"

# Run with 4 MPI processes
run-4: ddos_detector setup
	@echo "Running with 4 MPI processes (1 coordinator + 3 workers)..."
	mpiexec -n 4 ./ddos_detector data

# Run with 8 MPI processes
run-8: ddos_detector setup
	@echo "Running with 8 MPI processes (1 coordinator + 7 workers)..."
	mpiexec -n 8 ./ddos_detector data

# Test run with small dataset
test: ddos_detector setup
	@echo "Running test with 2 processes..."
	mpiexec -n 2 ./ddos_detector data

# Install MPI (for reference - platform specific)
install-mpi:
	@echo "Installing MS-MPI on Windows..."
	@echo "Download from: https://docs.microsoft.com/en-us/message-passing-interface/microsoft-mpi"
	@echo "Or install via package manager on Linux: sudo apt-get install mpich libmpich-dev"

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build all executables"
	@echo "  setup        - Create required directory structure"
	@echo "  preprocess   - Show preprocessing instructions"
	@echo "  run-4        - Run with 4 MPI processes"
	@echo "  run-8        - Run with 8 MPI processes"
	@echo "  test         - Run quick test"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove everything including results"
	@echo "  help         - Show this help message"

.PHONY: all clean distclean setup preprocess run-4 run-8 test install-mpi help
