#ifndef DETECTOR_H
#define DETECTOR_H

#include <sys/time.h>

#define MAX_FLOWS        100000
#define MAX_UNIQUE_IPS    4096
#define IP_STR_LEN          32
#define CUSUM_WINDOW       100
#define ML_FEATURES         10

typedef struct {
    char src_ip[IP_STR_LEN];
    char dst_ip[IP_STR_LEN];
    int  bytes;
    int  packets;
    int  timestamp;   /* seconds */
    int  protocol;    /* 6=TCP, 17=UDP */
    int  src_port;
    int  dst_port;
} FlowRecord;

typedef struct {
    char ip[IP_STR_LEN];
    int  packet_count;
    long byte_count;
} IpStat;

typedef struct {
    char  top_ip[IP_STR_LEN];
    double entropy;
    double avg_rate;      /* packets per second */
    double spike_score;   /* simple deviation score */
    int    total_packets;
    int    total_flows;
    int    unique_ips;
    
    /* Advanced features for ML */
    double flow_duration_mean;
    double flow_duration_std;
    double packet_size_mean;
    double packet_size_std;
    double syn_ratio;
    double udp_ratio;
} Features;

/* CUSUM state for statistical detection */
typedef struct {
    double cumsum_pos;
    double cumsum_neg;
    double mean;
    double std;
    int sample_count;
    double history[CUSUM_WINDOW];
} CusumState;

/* ML-based detection state */
typedef struct {
    double feature_vector[ML_FEATURES];
    double weights[ML_FEATURES];
    double threshold;
    int trained;
} MLDetector;

typedef struct {
    int    worker_rank;
    int    attack_flag;         /* 0 = normal, 1 = suspicious */
    char   suspicious_ip[IP_STR_LEN];
    double entropy;
    double avg_rate;
    double spike_score;
    int    total_packets;
    int    total_flows;
    
    /* Detection method flags */
    int entropy_detected;
    int cusum_detected;
    int ml_detected;
    
    /* Performance metrics */
    double processing_time_ms;
    long memory_used_kb;
    
    /* Accuracy metrics */
    int true_label;  /* 1=attack, 0=benign from dataset */
} Alert;

/* Performance metrics */
typedef struct {
    double detection_latency_ms;
    double throughput_pps;        /* packets per second */
    double throughput_gbps;       /* gigabits per second */
    int packets_processed;
    long bytes_processed;
    
    /* Accuracy metrics */
    int true_positives;
    int false_positives;
    int true_negatives;
    int false_negatives;
    
    /* Resource metrics */
    double cpu_usage_percent;
    long memory_usage_kb;
    double mpi_comm_overhead_ms;
} PerformanceMetrics;

/* Blocking statistics */
typedef struct {
    char blocked_ip[IP_STR_LEN];
    int attack_packets_blocked;
    int legitimate_packets_blocked;
    double blocking_efficiency;
    double collateral_damage;
    double block_time_ms;
} BlockingStats;

/* Exposed functions used by main.c */
void worker_start(int rank, int world_size, const char *dataset_root);
void coordinator_start(int world_size, const char *dataset_root);

/* Utility functions */
double get_time_ms(void);
void init_performance_metrics(PerformanceMetrics *metrics);
void calculate_accuracy_metrics(PerformanceMetrics *metrics);
void log_performance_metrics(const PerformanceMetrics *metrics, const char *filename);
void log_blocking_stats(const BlockingStats *stats, const char *filename);

#endif /* DETECTOR_H */