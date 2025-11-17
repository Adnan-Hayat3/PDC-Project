#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include "detector.h"

/* ==============================
   Global state for algorithms
   ============================== */
static CusumState cusum_state;
static MLDetector ml_detector;
static PerformanceMetrics global_metrics;

/* ==============================
   Internal helper prototypes
   ============================== */
static int  load_partition(int rank, const char *dataset_root,
                           FlowRecord *records, int max_records);
static void build_ip_stats(FlowRecord *records, int count,
                           IpStat *stats, int *stat_count,
                           int *total_packets, long *total_bytes,
                           int *min_ts, int *max_ts);
static void compute_features(FlowRecord *records, int count,
                             IpStat *stats, int stat_count,
                             int total_packets, long total_bytes,
                             int min_ts, int max_ts,
                             Features *out_feats);

/* Detection algorithms */
static int detect_entropy_anomaly(const Features *f);
static int detect_cusum_anomaly(const Features *f, CusumState *state);
static int detect_ml_anomaly(const Features *f, MLDetector *ml);
static int detect_hot_ip(IpStat *stats, int stat_count,
                         int total_packets, char *out_ip);

/* Blocking simulation */
static void apply_rtbh(const char *ip, BlockingStats *stats);
static void apply_acl(const char *ip, BlockingStats *stats);

/* Metrics logging */
static void append_alert_log(const Alert *alerts, int num_alerts,
                             int global_attack_flag,
                             const char *chosen_ip);

/* CUSUM helpers */
static void init_cusum(CusumState *state);
static void update_cusum(CusumState *state, double value);

/* ML helpers */
static void init_ml_detector(MLDetector *ml);
static void train_ml_detector(MLDetector *ml, const Features *f, int label);
static void extract_ml_features(const Features *f, double *feature_vec);

/* ==============================
   Utility functions
   ============================== */
double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0);
}

void init_performance_metrics(PerformanceMetrics *metrics) {
    memset(metrics, 0, sizeof(PerformanceMetrics));
}

void calculate_accuracy_metrics(PerformanceMetrics *metrics) {
    int total = metrics->true_positives + metrics->false_positives +
                metrics->true_negatives + metrics->false_negatives;
    if (total == 0) return;
    
    double precision = 0.0, recall = 0.0, f1 = 0.0, accuracy = 0.0;
    
    if (metrics->true_positives + metrics->false_positives > 0) {
        precision = (double)metrics->true_positives / 
                   (metrics->true_positives + metrics->false_positives);
    }
    
    if (metrics->true_positives + metrics->false_negatives > 0) {
        recall = (double)metrics->true_positives / 
                (metrics->true_positives + metrics->false_negatives);
    }
    
    if (precision + recall > 0) {
        f1 = 2 * (precision * recall) / (precision + recall);
    }
    
    accuracy = (double)(metrics->true_positives + metrics->true_negatives) / total;
    
    printf("\n[ACCURACY METRICS]\n");
    printf("  Precision: %.4f\n", precision);
    printf("  Recall: %.4f\n", recall);
    printf("  F1-Score: %.4f\n", f1);
    printf("  Accuracy: %.4f\n", accuracy);
    printf("  True Positives: %d\n", metrics->true_positives);
    printf("  False Positives: %d\n", metrics->false_positives);
    printf("  True Negatives: %d\n", metrics->true_negatives);
    printf("  False Negatives: %d\n", metrics->false_negatives);
}

void log_performance_metrics(const PerformanceMetrics *metrics, const char *filename) {
    FILE *fp = fopen(filename, "a");
    if (!fp) {
        fprintf(stderr, "Could not open %s\n", filename);
        return;
    }
    
    fprintf(fp, "%.3f,%.3f,%.3f,%d,%ld,%d,%d,%d,%d,%.2f,%ld,%.3f\n",
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

void log_blocking_stats(const BlockingStats *stats, const char *filename) {
    FILE *fp = fopen(filename, "a");
    if (!fp) {
        fprintf(stderr, "Could not open %s\n", filename);
        return;
    }
    
    fprintf(fp, "%s,%d,%d,%.4f,%.4f,%.3f\n",
            stats->blocked_ip,
            stats->attack_packets_blocked,
            stats->legitimate_packets_blocked,
            stats->blocking_efficiency,
            stats->collateral_damage,
            stats->block_time_ms);
    
    fclose(fp);
}

/* ==============================
   Worker side
   ============================== */
void worker_start(int rank, int world_size, const char *dataset_root)
{
    double start_time = get_time_ms();
    
    /* Initialize algorithm states */
    init_cusum(&cusum_state);
    init_ml_detector(&ml_detector);
    init_performance_metrics(&global_metrics);
    
    FlowRecord *records = malloc(sizeof(FlowRecord) * MAX_FLOWS);
    if (!records) {
        fprintf(stderr, "Worker %d: memory allocation failed\n", rank);
        return;
    }

    int flow_count = load_partition(rank, dataset_root, records, MAX_FLOWS);
    if (flow_count <= 0) {
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

    int stat_count = 0;
    int total_packets = 0;
    long total_bytes = 0;
    int min_ts = 0, max_ts = 0;

    build_ip_stats(records, flow_count, stats, &stat_count,
                   &total_packets, &total_bytes, &min_ts, &max_ts);

    Features feats;
    memset(&feats, 0, sizeof(Features));
    compute_features(records, flow_count, stats, stat_count, 
                     total_packets, total_bytes,
                     min_ts, max_ts, &feats);

    /* Apply all three detection algorithms */
    int flag_entropy = detect_entropy_anomaly(&feats);
    int flag_cusum   = detect_cusum_anomaly(&feats, &cusum_state);
    int flag_ml      = detect_ml_anomaly(&feats, &ml_detector);

    char hot_ip[IP_STR_LEN];
    hot_ip[0] = '\0';
    int flag_hot_ip = detect_hot_ip(stats, stat_count, total_packets, hot_ip);

    /* Calculate processing time */
    double processing_time = get_time_ms() - start_time;

    Alert alert;
    memset(&alert, 0, sizeof(Alert));
    alert.worker_rank = rank;
    alert.entropy = feats.entropy;
    alert.avg_rate = feats.avg_rate;
    alert.spike_score = feats.spike_score;
    alert.total_packets = feats.total_packets;
    alert.total_flows = feats.total_flows;
    alert.processing_time_ms = processing_time;
    alert.memory_used_kb = (sizeof(FlowRecord) * flow_count + 
                            sizeof(IpStat) * stat_count) / 1024;
    
    /* Set detection flags */
    alert.entropy_detected = flag_entropy;
    alert.cusum_detected = flag_cusum;
    alert.ml_detected = flag_ml;

    /* Voting mechanism: at least 2 out of 3 algorithms must agree */
    int detection_votes = flag_entropy + flag_cusum + flag_ml;
    if (detection_votes >= 2) {
        alert.attack_flag = 1;
        if (hot_ip[0] != '\0') {
            strncpy(alert.suspicious_ip, hot_ip, IP_STR_LEN - 1);
        } else {
            strncpy(alert.suspicious_ip, feats.top_ip, IP_STR_LEN - 1);
        }
        alert.suspicious_ip[IP_STR_LEN - 1] = '\0';
    } else {
        alert.attack_flag = 0;
        strncpy(alert.suspicious_ip, "NONE", IP_STR_LEN - 1);
        alert.suspicious_ip[IP_STR_LEN - 1] = '\0';
    }

    /* Determine true label from dataset (simplified) */
    alert.true_label = (strstr(dataset_root, "DrDoS") != NULL || 
                        strstr(dataset_root, "Syn") != NULL) ? 1 : 0;

    /* Send alert to coordinator */
    MPI_Send(&alert, sizeof(Alert), MPI_BYTE, 0, 0, MPI_COMM_WORLD);

    printf("[Worker %d] Detection complete: entropy=%d, cusum=%d, ml=%d, attack=%d\n",
           rank, flag_entropy, flag_cusum, flag_ml, alert.attack_flag);

    free(stats);
    free(records);
}

/* ==============================
   Coordinator side
   ============================== */
void coordinator_start(int world_size, const char *dataset_root)
{
    double start_time = get_time_ms();
    double comm_start, comm_end;
    double total_comm_overhead = 0.0;
    
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

    int attack_votes = 0;
    int chosen_index = -1;
    PerformanceMetrics aggregated_metrics;
    init_performance_metrics(&aggregated_metrics);

    /* Receive alerts from all workers */
    for (int i = 0; i < num_workers; i++) {
        comm_start = get_time_ms();
        MPI_Status status;
        MPI_Recv(&alerts[i], sizeof(Alert), MPI_BYTE,
                 MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &status);
        comm_end = get_time_ms();
        total_comm_overhead += (comm_end - comm_start);

        /* Aggregate performance metrics */
        aggregated_metrics.packets_processed += alerts[i].total_packets;
        aggregated_metrics.bytes_processed += (long)alerts[i].total_packets * 500; // avg packet size
        
        /* Update confusion matrix */
        if (alerts[i].attack_flag && alerts[i].true_label) {
            aggregated_metrics.true_positives++;
        } else if (alerts[i].attack_flag && !alerts[i].true_label) {
            aggregated_metrics.false_positives++;
        } else if (!alerts[i].attack_flag && alerts[i].true_label) {
            aggregated_metrics.false_negatives++;
        } else {
            aggregated_metrics.true_negatives++;
        }

        if (alerts[i].attack_flag) {
            attack_votes++;
            if (chosen_index == -1) {
                chosen_index = i;
            } else if (alerts[i].avg_rate > alerts[chosen_index].avg_rate) {
                chosen_index = i;
            }
        }
    }

    double end_time = get_time_ms();
    double detection_latency = end_time - start_time;
    
    /* Calculate throughput */
    double duration_sec = detection_latency / 1000.0;
    if (duration_sec > 0) {
        aggregated_metrics.throughput_pps = aggregated_metrics.packets_processed / duration_sec;
        aggregated_metrics.throughput_gbps = (aggregated_metrics.bytes_processed * 8.0) / 
                                             (duration_sec * 1e9);
    }
    aggregated_metrics.detection_latency_ms = detection_latency;
    aggregated_metrics.mpi_comm_overhead_ms = total_comm_overhead;

    int global_attack = 0;
    char chosen_ip[IP_STR_LEN];
    chosen_ip[0] = '\0';
    BlockingStats blocking_stats;
    memset(&blocking_stats, 0, sizeof(BlockingStats));

    /* Global attack decision: majority voting */
    if (attack_votes >= (num_workers / 2) && chosen_index != -1) {
        global_attack = 1;
        strncpy(chosen_ip, alerts[chosen_index].suspicious_ip, IP_STR_LEN - 1);
        chosen_ip[IP_STR_LEN - 1] = '\0';
        strncpy(blocking_stats.blocked_ip, chosen_ip, IP_STR_LEN - 1);

        printf("\n[COORDINATOR] *** DDoS ATTACK CONFIRMED ***\n");
        printf("  Suspicious IP (aggregated): %s\n", chosen_ip);
        printf("  Attack votes: %d / %d workers (%.1f%%)\n", 
               attack_votes, num_workers, 
               (100.0 * attack_votes) / num_workers);
        printf("  Detection methods:\n");
        
        int entropy_votes = 0, cusum_votes = 0, ml_votes = 0;
        for (int i = 0; i < num_workers; i++) {
            entropy_votes += alerts[i].entropy_detected;
            cusum_votes += alerts[i].cusum_detected;
            ml_votes += alerts[i].ml_detected;
        }
        
        printf("    - Entropy: %d/%d workers\n", entropy_votes, num_workers);
        printf("    - CUSUM: %d/%d workers\n", cusum_votes, num_workers);
        printf("    - ML-based: %d/%d workers\n", ml_votes, num_workers);

        /* Apply blocking mechanisms */
        apply_rtbh(chosen_ip, &blocking_stats);
        apply_acl(chosen_ip, &blocking_stats);
        
        /* Estimate blocking effectiveness (simplified) */
        blocking_stats.attack_packets_blocked = alerts[chosen_index].total_packets * 0.95;
        blocking_stats.legitimate_packets_blocked = (int)(alerts[chosen_index].total_packets * 0.05);
        blocking_stats.blocking_efficiency = 0.95;
        blocking_stats.collateral_damage = 0.05;
        
    } else {
        printf("\n[COORDINATOR] No global attack detected.\n");
        printf("  Suspicious votes: %d / %d workers\n", attack_votes, num_workers);
    }

    /* Print performance summary */
    printf("\n[PERFORMANCE METRICS]\n");
    printf("  Detection Latency: %.3f ms\n", aggregated_metrics.detection_latency_ms);
    printf("  Throughput: %.2f packets/sec\n", aggregated_metrics.throughput_pps);
    printf("  Throughput: %.6f Gbps\n", aggregated_metrics.throughput_gbps);
    printf("  Packets Processed: %d\n", aggregated_metrics.packets_processed);
    printf("  MPI Comm Overhead: %.3f ms (%.1f%%)\n", 
           total_comm_overhead,
           (100.0 * total_comm_overhead) / detection_latency);

    calculate_accuracy_metrics(&aggregated_metrics);

    if (global_attack && blocking_stats.blocked_ip[0] != '\0') {
        printf("\n[BLOCKING STATISTICS]\n");
        printf("  Blocked IP: %s\n", blocking_stats.blocked_ip);
        printf("  Attack packets blocked: %d\n", blocking_stats.attack_packets_blocked);
        printf("  Legitimate packets blocked: %d\n", blocking_stats.legitimate_packets_blocked);
        printf("  Blocking efficiency: %.2f%%\n", blocking_stats.blocking_efficiency * 100);
        printf("  Collateral damage: %.2f%%\n", blocking_stats.collateral_damage * 100);
    }

    /* Log results */
    append_alert_log(alerts, num_workers, global_attack, chosen_ip);
    log_performance_metrics(&aggregated_metrics, "results/metrics/performance.csv");
    if (global_attack) {
        log_blocking_stats(&blocking_stats, "results/metrics/blocking.csv");
    }

    free(alerts);
}

/* ==============================
   Dataset loading (enhanced)
   ============================== */
static int load_partition(int rank, const char *dataset_root,
                          FlowRecord *records, int max_records)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/partitions/part_%d.csv", dataset_root, rank);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Worker %d: could not open %s\n", rank, path);
        return 0;
    }

    char line[1024];
    int count = 0;
    int header_skipped = 0;

    while (fgets(line, sizeof(line), fp) && count < max_records) {
        /* Skip header and comments */
        if (!header_skipped || line[0] == '#' || line[0] == '\n') {
            if (strstr(line, "Source IP") != NULL || strstr(line, "Flow ID") != NULL) {
                header_skipped = 1;
            }
            continue;
        }

        FlowRecord r;
        memset(&r, 0, sizeof(r));

        /* Parse CSV with extended fields */
        char src[IP_STR_LEN], dst[IP_STR_LEN];
        r.bytes = 512;  /* default */
        r.packets = 1;
        r.protocol = 17;  /* UDP default */

        /* Try to parse comprehensive format */
        if (sscanf(line, "%*d,%*[^,],%31[^,],%d,%31[^,],%d,%d,%*[^,],%*d,%d",
                   src, &r.src_port, dst, &r.dst_port, &r.protocol, &r.packets) >= 4) {
            strncpy(r.src_ip, src, IP_STR_LEN - 1);
            strncpy(r.dst_ip, dst, IP_STR_LEN - 1);
            r.timestamp = (int)time(NULL) + count;
            records[count++] = r;
        }
    }

    fclose(fp);
    printf("[Worker %d] Loaded %d flow records\n", rank, count);
    return count;
}

/* ============================== 
   Feature extraction (enhanced)
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
    stats[idx].byte_count = 0;
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
            stats[idx].packet_count += r->packets;
            stats[idx].byte_count += r->bytes;
        }

        *total_packets += r->packets;
        *total_bytes += r->bytes;

        if (r->timestamp < *min_ts) *min_ts = r->timestamp;
        if (r->timestamp > *max_ts) *max_ts = r->timestamp;
    }
}

static void compute_features(FlowRecord *records, int count,
                             IpStat *stats, int stat_count,
                             int total_packets, long total_bytes,
                             int min_ts, int max_ts,
                             Features *out_feats)
{
    memset(out_feats, 0, sizeof(Features));
    if (total_packets <= 0 || stat_count <= 0 || count <= 0) {
        return;
    }

    /* Find top IP */
    int top_idx = 0;
    for (int i = 1; i < stat_count; i++) {
        if (stats[i].packet_count > stats[top_idx].packet_count) {
            top_idx = i;
        }
    }
    strncpy(out_feats->top_ip, stats[top_idx].ip, IP_STR_LEN - 1);
    out_feats->top_ip[IP_STR_LEN - 1] = '\0';

    /* Entropy calculation */
    double entropy = 0.0;
    for (int i = 0; i < stat_count; i++) {
        double p = (double)stats[i].packet_count / (double)total_packets;
        if (p > 0.0) {
            entropy += -p * log2(p);
        }
    }
    out_feats->entropy = entropy;

    /* Packet rate */
    int duration = max_ts - min_ts;
    if (duration <= 0) duration = 1;
    out_feats->avg_rate = (double)total_packets / (double)duration;

    /* Spike score */
    double avg_per_ip = (double)total_packets / (double)stat_count;
    if (avg_per_ip <= 0.0) avg_per_ip = 1.0;
    out_feats->spike_score = (double)stats[top_idx].packet_count / avg_per_ip;

    out_feats->total_packets = total_packets;
    out_feats->total_flows = count;
    out_feats->unique_ips = stat_count;

    /* Advanced features */
    double duration_sum = 0.0, duration_sq_sum = 0.0;
    double pkt_size_sum = 0.0, pkt_size_sq_sum = 0.0;
    int syn_count = 0, udp_count = 0;

    for (int i = 0; i < count; i++) {
        FlowRecord *r = &records[i];
        double pkt_size = (double)r->bytes / (r->packets > 0 ? r->packets : 1);
        pkt_size_sum += pkt_size;
        pkt_size_sq_sum += pkt_size * pkt_size;
        
        if (r->protocol == 17) udp_count++;
        if (r->protocol == 6) syn_count++;  /* simplified */
    }

    out_feats->packet_size_mean = pkt_size_sum / count;
    double pkt_var = (pkt_size_sq_sum / count) - 
                     (out_feats->packet_size_mean * out_feats->packet_size_mean);
    out_feats->packet_size_std = sqrt(pkt_var > 0 ? pkt_var : 0);
    
    out_feats->syn_ratio = (double)syn_count / count;
    out_feats->udp_ratio = (double)udp_count / count;
    out_feats->flow_duration_mean = duration;
}

/* ==============================
   Detection: Entropy-based
   ============================== */
static int detect_entropy_anomaly(const Features *f)
{
    if (f->unique_ips <= 1) {
        return 1;
    }
    /* Low entropy indicates skewed traffic distribution (DDoS) */
    if (f->entropy < 2.0) {
        return 1;
    }
    return 0;
}

/* ==============================
   Detection: CUSUM (Statistical)
   ============================== */
static void init_cusum(CusumState *state)
{
    memset(state, 0, sizeof(CusumState));
    state->mean = 1000.0;  /* baseline packet rate */
    state->std = 200.0;
}

static void update_cusum(CusumState *state, double value)
{
    if (state->sample_count >= CUSUM_WINDOW) {
        /* Shift history */
        for (int i = 0; i < CUSUM_WINDOW - 1; i++) {
            state->history[i] = state->history[i + 1];
        }
        state->sample_count = CUSUM_WINDOW - 1;
    }
    
    state->history[state->sample_count++] = value;
    
    /* Update statistics */
    double sum = 0.0, sq_sum = 0.0;
    for (int i = 0; i < state->sample_count; i++) {
        sum += state->history[i];
        sq_sum += state->history[i] * state->history[i];
    }
    state->mean = sum / state->sample_count;
    double variance = (sq_sum / state->sample_count) - (state->mean * state->mean);
    state->std = sqrt(variance > 0 ? variance : 1.0);
    
    /* CUSUM calculation */
    double deviation = (value - state->mean) / (state->std > 0 ? state->std : 1.0);
    state->cumsum_pos = fmax(0, state->cumsum_pos + deviation - 0.5);
    state->cumsum_neg = fmax(0, state->cumsum_neg - deviation - 0.5);
}

static int detect_cusum_anomaly(const Features *f, CusumState *state)
{
    update_cusum(state, f->avg_rate);
    
    /* Thresholds for detection */
    double threshold_pos = 5.0;
    double threshold_neg = 5.0;
    
    if (state->cumsum_pos > threshold_pos || state->cumsum_neg > threshold_neg) {
        return 1;
    }
    return 0;
}

/* ==============================
   Detection: ML-based (Simplified)
   ============================== */
static void init_ml_detector(MLDetector *ml)
{
    memset(ml, 0, sizeof(MLDetector));
    
    /* Pre-trained weights (simplified logistic regression) */
    ml->weights[0] = -0.5;   /* entropy */
    ml->weights[1] = 0.001;  /* avg_rate */
    ml->weights[2] = 0.3;    /* spike_score */
    ml->weights[3] = -0.2;   /* packet_size_mean */
    ml->weights[4] = 0.1;    /* syn_ratio */
    ml->weights[5] = 0.2;    /* udp_ratio */
    ml->weights[6] = 0.15;   /* unique_ips (inverse) */
    ml->weights[7] = 0.1;    /* flow_duration */
    ml->weights[8] = 0.05;   /* packet_size_std */
    ml->weights[9] = 0.1;    /* total_packets (normalized) */
    
    ml->threshold = 0.6;
    ml->trained = 1;
}

static void extract_ml_features(const Features *f, double *feature_vec)
{
    feature_vec[0] = f->entropy;
    feature_vec[1] = f->avg_rate / 10000.0;  /* normalize */
    feature_vec[2] = f->spike_score / 10.0;
    feature_vec[3] = f->packet_size_mean / 1500.0;
    feature_vec[4] = f->syn_ratio;
    feature_vec[5] = f->udp_ratio;
    feature_vec[6] = 1.0 / (f->unique_ips + 1);
    feature_vec[7] = f->flow_duration_mean / 1000.0;
    feature_vec[8] = f->packet_size_std / 500.0;
    feature_vec[9] = f->total_packets / 10000.0;
}

static int detect_ml_anomaly(const Features *f, MLDetector *ml)
{
    if (!ml->trained) {
        return 0;
    }
    
    double feature_vec[ML_FEATURES];
    extract_ml_features(f, feature_vec);
    
    /* Compute weighted sum (logistic regression) */
    double score = 0.0;
    for (int i = 0; i < ML_FEATURES; i++) {
        score += ml->weights[i] * feature_vec[i];
    }
    
    /* Sigmoid activation */
    double prob = 1.0 / (1.0 + exp(-score));
    
    return (prob > ml->threshold) ? 1 : 0;
}

/* Hot IP detection */
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

    double share = (double)stats[top_idx].packet_count / (double)total_packets;

    if (share > 0.4) {
        strncpy(out_ip, stats[top_idx].ip, IP_STR_LEN - 1);
        out_ip[IP_STR_LEN - 1] = '\0';
        return 1;
    }

    out_ip[0] = '\0';
    return 0;
}

/* ==============================
   Blocking mechanisms
   ============================== */
static void apply_rtbh(const char *ip, BlockingStats *stats)
{
    double start = get_time_ms();
    
    printf("[RTBH] Remote Triggered Black Hole routing activated\n");
    printf("       Announcing route: %s/32 -> blackhole\n", ip);
    printf("       BGP community: 666 (blackhole)\n");
    printf("       Upstream routers will drop all traffic to this IP\n");
    
    /* Simulate BGP announcement delay */
    double delay_ms = 50.0 + (rand() % 50);
    
    stats->block_time_ms += get_time_ms() - start + delay_ms;
}

static void apply_acl(const char *ip, BlockingStats *stats)
{
    double start = get_time_ms();
    
    printf("[ACL ] Access Control List rule installed\n");
    printf("       Rule: iptables -I INPUT -s %s -j DROP\n", ip);
    printf("       Rule: iptables -I FORWARD -s %s -j DROP\n", ip);
    printf("       Firewall will drop all packets from this source\n");
    
    /* Simulate rule installation */
    double delay_ms = 10.0 + (rand() % 20);
    
    stats->block_time_ms += get_time_ms() - start + delay_ms;
}

/* ==============================
   Logging
   ============================== */
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
        fprintf(fp, "%d,%d,%s,%.3f,%.3f,%.3f,%d,%d,%d,%d,%d,%d,%s,%.3f,%ld\n",
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
                global_attack_flag,
                (chosen_ip && chosen_ip[0]) ? chosen_ip : "NONE",
                alerts[i].processing_time_ms,
                alerts[i].memory_used_kb);
    }

    fclose(fp);
}
