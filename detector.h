#ifndef DETECTOR_H
#define DETECTOR_H

#define MAX_FLOWS        100000
#define MAX_UNIQUE_IPS    4096
#define IP_STR_LEN          32

typedef struct {
    char src_ip[IP_STR_LEN];
    char dst_ip[IP_STR_LEN];
    int  bytes;
    int  timestamp;   /* seconds */
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
} Features;

typedef struct {
    int    worker_rank;
    int    attack_flag;         /* 0 = normal, 1 = suspicious */
    char   suspicious_ip[IP_STR_LEN];
    double entropy;
    double avg_rate;
    double spike_score;
    int    total_packets;
    int    total_flows;
} Alert;

/* Exposed functions used by main.c */
void worker_start(int rank, int world_size, const char *dataset_root);
void coordinator_start(int world_size, const char *dataset_root);

#endif /* DETECTOR_H */