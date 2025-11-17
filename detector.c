#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "detector.h"

/* ==============================
   Internal helper prototypes
   ============================== */
static int  load_partition(int rank, const char *dataset_root,
                           FlowRecord *records, int max_records);
static void build_ip_stats(FlowRecord *records, int count,
                           IpStat *stats, int *stat_count,
                           int *total_packets, long *total_bytes,
                           int *min_ts, int *max_ts);
static void compute_features(IpStat *stats, int stat_count,
                             int total_packets, long total_bytes,
                             int min_ts, int max_ts,
                             Features *out_feats);

/* detection methods */
static int detect_entropy_anomaly(const Features *f);
static int detect_rate_anomaly(const Features *f);
static int detect_hot_ip(IpStat *stats, int stat_count,
                         int total_packets, char *out_ip);
static int detect_cusum_anomaly(const Features *f, CusumState *cusum);
static int detect_ml_anomaly(const Features *f, MLDetector *ml);
static void init_cusum_state(CusumState *cusum);
static void init_ml_detector(MLDetector *ml);

/* blocking simulation */
static void apply_rtbh(const char *ip, BlockingStats *stats);
static void apply_acl(const char *ip, BlockingStats *stats);

/* performance utilities */
static double get_time_ms(void);
static void init_performance_metrics(PerformanceMetrics *metrics);
static void calculate_accuracy_metrics(PerformanceMetrics *metrics);
static void log_performance_metrics(const PerformanceMetrics *metrics, const char *filename);
static void log_blocking_stats(const BlockingStats *stats, const char *filename);

/* metrics logging */
static void append_alert_log(const Alert *alerts, int num_alerts,
                             int global_attack_flag,
                             const char *chosen_ip);

/* ==============================
   Worker side
   ============================== */
void worker_start(int rank, int world_size, const char *dataset_root)
{
    double start_time = get_time_ms();
    
    FlowRecord *records = malloc(sizeof(FlowRecord) * MAX_FLOWS);
    if (!records) {
        fprintf(stderr, "Worker %d: memory allocation failed\n", rank);
        return;
    }

    int flow_count = load_partition(rank, dataset_root, records, MAX_FLOWS);
    if (flow_count <= 0) {
        /* Send a "no data" alert */
        Alert alert;
        memset(&alert, 0, sizeof(Alert));
        alert.worker_rank = rank;
        MPI_Send(&alert, sizeof(Alert), MPI_BYTE, 0, 0, MPI_COMM_WORLD);
        free(records);
        return;
    }

    IpStat *stats = malloc(sizeof(IpStat) * MAX_UNIQUE_IPS);
    if (!stats) {
        fprintf(stderr, "Worker %d: stats allocation failed\n", rank);
        free(records);
        return;
    }
    
    /* Initialize detection algorithms */
    CusumState cusum;
    MLDetector ml;
    init_cusum_state(&cusum);
    init_ml_detector(&ml);

    int stat_count = 0;
    int total_packets = 0;
    long total_bytes = 0;
    int min_ts = 0, max_ts = 0;

    build_ip_stats(records, flow_count, stats, &stat_count,
                   &total_packets, &total_bytes, &min_ts, &max_ts);

    Features feats;
    memset(&feats, 0, sizeof(Features));
    compute_features(stats, stat_count, total_packets, total_bytes,
                     min_ts, max_ts, &feats);

    /* Run all three detection algorithms */
    int flag_entropy = detect_entropy_anomaly(&feats);
    int flag_cusum   = detect_cusum_anomaly(&feats, &cusum);
    int flag_ml      = detect_ml_anomaly(&feats, &ml);

    char hot_ip[IP_STR_LEN];
    hot_ip[0] = '\0';
    int flag_hot_ip  = detect_hot_ip(stats, stat_count,
                                     total_packets, hot_ip);

    Alert alert;
    memset(&alert, 0, sizeof(Alert));
    alert.worker_rank = rank;
    alert.entropy     = feats.entropy;
    alert.avg_rate    = feats.avg_rate;
    alert.spike_score = feats.spike_score;
    alert.total_packets = feats.total_packets;
    alert.total_flows   = feats.total_flows;
    
    /* Detection flags */
    alert.entropy_detected = flag_entropy;
    alert.cusum_detected   = flag_cusum;
    alert.ml_detected      = flag_ml;

    /* Voting: attack if at least 2 out of 3 algorithms detect anomaly */
    if (flag_entropy + flag_cusum + flag_ml >= 2) {
        alert.attack_flag = 1;
        if (hot_ip[0] != '\0') {
            strncpy(alert.suspicious_ip, hot_ip, IP_STR_LEN - 1);
            alert.suspicious_ip[IP_STR_LEN - 1] = '\0';
        } else {
            strncpy(alert.suspicious_ip, feats.top_ip, IP_STR_LEN - 1);
            alert.suspicious_ip[IP_STR_LEN - 1] = '\0';
        }
    } else {
        alert.attack_flag = 0;
        strncpy(alert.suspicious_ip, "NONE", IP_STR_LEN - 1);
        alert.suspicious_ip[IP_STR_LEN - 1] = '\0';
    }
    
    /* Performance metrics */
    double end_time = get_time_ms();
    alert.processing_time_ms = end_time - start_time;
    alert.memory_used_kb = (sizeof(FlowRecord) * flow_count + 
                           sizeof(IpStat) * stat_count) / 1024;

    MPI_Send(&alert, sizeof(Alert), MPI_BYTE, 0, 0, MPI_COMM_WORLD);

    free(stats);
    free(records);
}

/* ==============================
   Coordinator side
   ============================== */
void coordinator_start(int world_size, const char *dataset_root)
{
    (void)dataset_root; /* currently unused, keep signature flexible */

    int num_workers = world_size - 1;
    if (num_workers <= 0) {
        fprintf(stderr, "Coordinator: no workers\n");
        return;
    }

    Alert *alerts = malloc(sizeof(Alert) * num_workers);
    if (!alerts) {
        fprintf(stderr, "Coordinator: alert allocation failed\n");
        return;
    }

    int i;
    int attack_votes = 0;
    int chosen_index = -1;

    for (i = 0; i < num_workers; i++) {
        MPI_Status status;
        MPI_Recv(&alerts[i], sizeof(Alert), MPI_BYTE,
                 MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &status);

        if (alerts[i].attack_flag) {
            attack_votes++;

            /* simple rule: pick first suspicious IP with highest avg_rate */
            if (chosen_index == -1) {
                chosen_index = i;
            } else if (alerts[i].avg_rate > alerts[chosen_index].avg_rate) {
                chosen_index = i;
            }
        }
    }

    int global_attack = 0;
    char chosen_ip[IP_STR_LEN];
    chosen_ip[0] = '\0';

    if (attack_votes >= 2 && chosen_index != -1) {
        global_attack = 1;
        strncpy(chosen_ip, alerts[chosen_index].suspicious_ip,
                IP_STR_LEN - 1);
        chosen_ip[IP_STR_LEN - 1] = '\0';

        printf("\n[COORDINATOR] DDoS attack CONFIRMED.\n");
        printf("  Suspicious IP (aggregated): %s\n", chosen_ip);
        printf("  Votes: %d / %d workers\n", attack_votes, num_workers);
        printf("  Detection methods: Entropy=%d, CUSUM=%d, ML=%d\n",
               alerts[chosen_index].entropy_detected,
               alerts[chosen_index].cusum_detected,
               alerts[chosen_index].ml_detected);

        /* Apply blocking with statistics tracking */
        BlockingStats block_stats;
        memset(&block_stats, 0, sizeof(BlockingStats));
        strncpy(block_stats.blocked_ip, chosen_ip, IP_STR_LEN - 1);
        
        double block_start = get_time_ms();
        apply_rtbh(chosen_ip, &block_stats);
        apply_acl(chosen_ip, &block_stats);
        block_stats.block_time_ms = get_time_ms() - block_start;
        
        log_blocking_stats(&block_stats, "results/metrics/blocking.csv");
    } else {
        printf("\n[COORDINATOR] No global attack detected.\n");
        printf("  Suspicious votes: %d / %d workers\n",
               attack_votes, num_workers);
    }

    append_alert_log(alerts, num_workers, global_attack, chosen_ip);

    free(alerts);
}

/* ==============================
   Dataset loading
   ============================== */
/*
   Expected per-partition CSV format:
   src_ip,dst_ip,bytes,timestamp,protocol,src_port,dst_port,packets

   Example:
   192.168.1.10,10.0.0.5,512,1700000001,17,60954,29816,2
*/
static int load_partition(int rank, const char *dataset_root,
                          FlowRecord *records, int max_records)
{
    char path[512];
    snprintf(path, sizeof(path),
             "%s/partitions/part_%d.csv", dataset_root, rank);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Worker %d: could not open %s\n", rank, path);
        return 0;
    }

    char line[1024];
    int count = 0;
    int header_skipped = 0;

    while (fgets(line, sizeof(line), fp) && count < max_records) {
        if (!header_skipped) {
            header_skipped = 1;
            continue;
        }
        
        if (line[0] == '#' || line[0] == '\n')
            continue;

        FlowRecord r;
        memset(&r, 0, sizeof(r));

        /* Parse: src_ip,dst_ip,bytes,timestamp,protocol,src_port,dst_port,packets */
        char src[IP_STR_LEN], dst[IP_STR_LEN];
        int bytes = 0, ts = 0, proto = 0, sport = 0, dport = 0, pkts = 0;

        int parsed = sscanf(line, "%31[^,],%31[^,],%d,%d,%d,%d,%d,%d",
                           src, dst, &bytes, &ts, &proto, &sport, &dport, &pkts);
        
        if (parsed >= 4) {
            strncpy(r.src_ip, src, IP_STR_LEN - 1);
            strncpy(r.dst_ip, dst, IP_STR_LEN - 1);
            r.bytes = bytes;
            r.timestamp = ts;
            r.protocol = proto;
            r.src_port = sport;
            r.dst_port = dport;
            r.packets = (pkts > 0) ? pkts : 1;
            records[count++] = r;
        }
    }

    fclose(fp);
    
    if (count > 0) {
        printf("Worker %d: loaded %d records from %s\n", rank, count, path);
    }
    
    return count;
}

/* ==============================
   IP stats & feature extraction
   ============================== */
static int find_or_add_ip(IpStat *stats, int *stat_count, const char *ip)
{
    for (int i = 0; i < *stat_count; i++) {
        if (strcmp(stats[i].ip, ip) == 0) {
            return i;
        }
    }
    if (*stat_count >= MAX_UNIQUE_IPS) {
        return -1;
    }
    int idx = *stat_count;
    strncpy(stats[idx].ip, ip, IP_STR_LEN - 1);
    stats[idx].ip[IP_STR_LEN - 1] = '\0';
    stats[idx].packet_count = 0;
    stats[idx].byte_count   = 0;
    (*stat_count)++;
    return idx;
}

static void build_ip_stats(FlowRecord *records, int count,
                           IpStat *stats, int *stat_count,
                           int *total_packets, long *total_bytes,
                           int *min_ts, int *max_ts)
{
    *stat_count = 0;
    *total_packets = 0;
    *total_bytes = 0;
    *min_ts = 0;
    *max_ts = 0;

    if (count <= 0) return;

    *min_ts = records[0].timestamp;
    *max_ts = records[0].timestamp;

    for (int i = 0; i < count; i++) {
        FlowRecord *r = &records[i];

        int idx = find_or_add_ip(stats, stat_count, r->src_ip);
        if (idx >= 0) {
            stats[idx].packet_count += 1;
            stats[idx].byte_count   += r->bytes;
        }

        *total_packets += 1;
        *total_bytes   += r->bytes;

        if (r->timestamp < *min_ts) *min_ts = r->timestamp;
        if (r->timestamp > *max_ts) *max_ts = r->timestamp;
    }
}

static void compute_features(IpStat *stats, int stat_count,
                             int total_packets, long total_bytes,
                             int min_ts, int max_ts,
                             Features *out_feats)
{
    memset(out_feats, 0, sizeof(Features));
    if (total_packets <= 0 || stat_count <= 0) {
        return;
    }

    /* top IP by packet count */
    int top_idx = 0;
    for (int i = 1; i < stat_count; i++) {
        if (stats[i].packet_count > stats[top_idx].packet_count) {
            top_idx = i;
        }
    }
    strncpy(out_feats->top_ip, stats[top_idx].ip, IP_STR_LEN - 1);
    out_feats->top_ip[IP_STR_LEN - 1] = '\0';

    /* entropy over src_ip distribution */
    double entropy = 0.0;
    for (int i = 0; i < stat_count; i++) {
        double p = (double)stats[i].packet_count / (double)total_packets;
        if (p > 0.0) {
            entropy += -p * log2(p);
        }
    }
    out_feats->entropy = entropy;

    /* avg packet rate (simple) */
    int duration = max_ts - min_ts;
    if (duration <= 0) duration = 1;
    out_feats->avg_rate = (double)total_packets / (double)duration;

    /* simple spike score: ratio of top IP vs average per IP */
    double avg_per_ip = (double)total_packets / (double)stat_count;
    if (avg_per_ip <= 0.0) avg_per_ip = 1.0;
    out_feats->spike_score =
        (double)stats[top_idx].packet_count / avg_per_ip;

    out_feats->total_packets = total_packets;
    out_feats->total_flows   = total_packets; /* here each record ~1 pkt */
    out_feats->unique_ips    = stat_count;
}

/* ==============================
   Detection algorithms
   ============================== */
static void init_cusum_state(CusumState *cusum)
{
    memset(cusum, 0, sizeof(CusumState));
    cusum->mean = 0.0;
    cusum->std = 0.0;
    cusum->sample_count = 0;
}

static void init_ml_detector(MLDetector *ml)
{
    memset(ml, 0, sizeof(MLDetector));
    /* Simple pre-trained weights (tune with actual training) */
    ml->weights[0] = -0.5;  /* entropy */
    ml->weights[1] = 0.3;   /* avg_rate */
    ml->weights[2] = 0.4;   /* spike_score */
    ml->weights[3] = 0.2;   /* unique_ips ratio */
    ml->threshold = 0.6;
    ml->trained = 1;
}

/* CUSUM: Cumulative Sum statistical detection */
static int detect_cusum_anomaly(const Features *f, CusumState *cusum)
{
    double value = f->avg_rate;
    
    /* Update running statistics */
    if (cusum->sample_count < CUSUM_WINDOW) {
        cusum->history[cusum->sample_count] = value;
        cusum->sample_count++;
        
        /* Calculate mean */
        double sum = 0.0;
        for (int i = 0; i < cusum->sample_count; i++) {
            sum += cusum->history[i];
        }
        cusum->mean = sum / cusum->sample_count;
        
        /* Calculate std */
        double var_sum = 0.0;
        for (int i = 0; i < cusum->sample_count; i++) {
            double diff = cusum->history[i] - cusum->mean;
            var_sum += diff * diff;
        }
        cusum->std = sqrt(var_sum / cusum->sample_count);
        
        return 0;  /* Not enough samples yet */
    }
    
    /* CUSUM calculation */
    double threshold = 5.0;  /* Detection threshold */
    double drift = cusum->std * 0.5;  /* Drift parameter */
    
    double deviation = value - cusum->mean - drift;
    cusum->cumsum_pos = fmax(0, cusum->cumsum_pos + deviation);
    cusum->cumsum_neg = fmax(0, cusum->cumsum_neg - deviation);
    
    if (cusum->cumsum_pos > threshold || cusum->cumsum_neg > threshold) {
        return 1;  /* Anomaly detected */
    }
    
    return 0;
}

/* Simple ML-based detection (logistic regression style) */
static int detect_ml_anomaly(const Features *f, MLDetector *ml)
{
    if (!ml->trained) return 0;
    
    /* Normalize and compute weighted sum */
    ml->feature_vector[0] = f->entropy / 10.0;  /* normalize */
    ml->feature_vector[1] = f->avg_rate / 10000.0;
    ml->feature_vector[2] = f->spike_score / 100.0;
    ml->feature_vector[3] = (double)f->unique_ips / 1000.0;
    
    double score = 0.0;
    for (int i = 0; i < 4; i++) {
        score += ml->weights[i] * ml->feature_vector[i];
    }
    
    /* Sigmoid activation */
    double prob = 1.0 / (1.0 + exp(-score));
    
    return (prob > ml->threshold) ? 1 : 0;
}

/* entropy check: if entropy drops below threshold, traffic is skewed */
static int detect_entropy_anomaly(const Features *f)
{
    if (f->unique_ips <= 1) {
        return 1;
    }

    /* example thresholds, you can tune from experiments */
    if (f->entropy < 1.0) {
        return 1;
    }
    return 0;
}

/* rate check: if avg packet rate is high, flag */
static int detect_rate_anomaly(const Features *f)
{
    /* tune thresholds in experiments */
    if (f->avg_rate > 5000.0) {
        return 1;
    }
    return 0;
}

/* hot IP check: if single IP dominates traffic */
static int detect_hot_ip(IpStat *stats, int stat_count,
                         int total_packets, char *out_ip)
{
    if (total_packets <= 0 || stat_count <= 0) {
        out_ip[0] = '\0';
        return 0;
    }

    int top_idx = 0;
    for (int i = 1; i < stat_count; i++) {
        if (stats[i].packet_count > stats[top_idx].packet_count) {
            top_idx = i;
        }
    }

    double share = (double)stats[top_idx].packet_count /
                   (double)total_packets;

    if (share > 0.4) { /* 40% of packets from one IP */
        strncpy(out_ip, stats[top_idx].ip, IP_STR_LEN - 1);
        out_ip[IP_STR_LEN - 1] = '\0';
        return 1;
    }

    out_ip[0] = '\0';
    return 0;
}

/* ==============================
   Blocking simulation
   ============================== */
static void apply_rtbh(const char *ip, BlockingStats *stats)
{
    printf("[RTBH] Blackholing traffic to/from IP: %s\n", ip);
    /* Simulate blocking efficiency */
    stats->attack_packets_blocked += 950;  /* 95% of attack traffic */
    stats->legitimate_packets_blocked += 10;  /* 1% collateral */
    stats->blocking_efficiency = 0.95;
    stats->collateral_damage = 0.01;
}

static void apply_acl(const char *ip, BlockingStats *stats)
{
    printf("[ACL ] Installing drop rule for IP: %s\n", ip);
    /* Simulate iptables rule installation */
    FILE *fp = fopen("results/metrics/iptables_rules.txt", "a");
    if (fp) {
        fprintf(fp, "iptables -A INPUT -s %s -j DROP\n", ip);
        fprintf(fp, "iptables -A OUTPUT -d %s -j DROP\n", ip);
        fclose(fp);
    }
}

/* ==============================
   Metrics logging
   ============================== */
static double get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0);
}

static void init_performance_metrics(PerformanceMetrics *metrics)
{
    memset(metrics, 0, sizeof(PerformanceMetrics));
}

static void calculate_accuracy_metrics(PerformanceMetrics *metrics)
{
    int total = metrics->true_positives + metrics->false_positives +
                metrics->true_negatives + metrics->false_negatives;
    if (total == 0) return;
    
    /* These would be calculated based on ground truth labels */
    printf("\n[METRICS] Accuracy Statistics:\n");
    printf("  True Positives:  %d\n", metrics->true_positives);
    printf("  False Positives: %d\n", metrics->false_positives);
    printf("  True Negatives:  %d\n", metrics->true_negatives);
    printf("  False Negatives: %d\n", metrics->false_negatives);
    
    double precision = (double)metrics->true_positives / 
                      (metrics->true_positives + metrics->false_positives);
    double recall = (double)metrics->true_positives / 
                   (metrics->true_positives + metrics->false_negatives);
    double f1 = 2 * (precision * recall) / (precision + recall);
    
    printf("  Precision: %.3f\n", precision);
    printf("  Recall:    %.3f\n", recall);
    printf("  F1-Score:  %.3f\n", f1);
}

static void log_performance_metrics(const PerformanceMetrics *metrics, const char *filename)
{
    FILE *fp = fopen(filename, "a");
    if (!fp) return;
    
    fprintf(fp, "%.3f,%.2f,%.2f,%d,%ld,%d,%d,%d,%d,%.2f,%ld,%.3f\n",
            metrics->detection_latency_ms,
            metrics->throughput_pps,
            metrics->throughput_gbps,
            metrics->packets_processed,
            metrics->bytes_processed,
            metrics->true_positives,
            metrics->false_positives,
            metrics->true_negatives,
            metrics->false_negatives,
            metrics->cpu_usage_percent,
            metrics->memory_usage_kb,
            metrics->mpi_comm_overhead_ms);
    
    fclose(fp);
}

static void log_blocking_stats(const BlockingStats *stats, const char *filename)
{
    FILE *fp = fopen(filename, "a");
    if (!fp) return;
    
    fprintf(fp, "%s,%d,%d,%.3f,%.3f,%.3f\n",
            stats->blocked_ip,
            stats->attack_packets_blocked,
            stats->legitimate_packets_blocked,
            stats->blocking_efficiency,
            stats->collateral_damage,
            stats->block_time_ms);
    
    fclose(fp);
}

static void append_alert_log(const Alert *alerts, int num_alerts,
                             int global_attack_flag,
                             const char *chosen_ip)
{
    FILE *fp = fopen("results/metrics/alerts.csv", "a");
    if (!fp) {
        fprintf(stderr, "Could not open results/metrics/alerts.csv\n");
        return;
    }

    for (int i = 0; i < num_alerts; i++) {
        fprintf(fp,
                "%d,%d,%s,%.3f,%.3f,%.3f,%d,%d,%d,%d,%d,%.3f,%ld,%d,%s\n",
                alerts[i].worker_rank,
                alerts[i].attack_flag,
                alerts[i].suspicious_ip,
                alerts[i].entropy,
                alerts[i].avg_rate,
                alerts[i].spike_score,
                alerts[i].total_packets,
                alerts[i].total_flows,
                alerts[i].entropy_detected,
                alerts[i].cusum_detected,
                alerts[i].ml_detected,
                alerts[i].processing_time_ms,
                alerts[i].memory_used_kb,
                global_attack_flag,
                (chosen_ip && chosen_ip[0]) ? chosen_ip : "NONE");
    }

    fclose(fp);
}
