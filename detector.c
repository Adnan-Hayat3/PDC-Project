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

/* blocking simulation */
static void apply_rtbh(const char *ip);
static void apply_acl(const char *ip);

/* metrics logging */
static void append_alert_log(const Alert *alerts, int num_alerts,
                             int global_attack_flag,
                             const char *chosen_ip);

/* ==============================
   Worker side
   ============================== */
void worker_start(int rank, int world_size, const char *dataset_root)
{
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

    int flag_entropy = detect_entropy_anomaly(&feats);
    int flag_rate    = detect_rate_anomaly(&feats);

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

    if (flag_entropy + flag_rate + flag_hot_ip >= 2) {
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

        apply_rtbh(chosen_ip);
        apply_acl(chosen_ip);
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
   src_ip,dst_ip,bytes,timestamp

   Example:
   192.168.1.10,10.0.0.5,512,1700000001
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

    char line[512];
    int count = 0;

    while (fgets(line, sizeof(line), fp) && count < max_records) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        FlowRecord r;
        memset(&r, 0, sizeof(r));

        /* basic parsing */
        char src[IP_STR_LEN], dst[IP_STR_LEN];
        int bytes = 0;
        int ts = 0;

        if (sscanf(line, "%31[^,],%31[^,],%d,%d",
                   src, dst, &bytes, &ts) == 4) {
            strncpy(r.src_ip, src, IP_STR_LEN - 1);
            strncpy(r.dst_ip, dst, IP_STR_LEN - 1);
            r.bytes = bytes;
            r.timestamp = ts;
            records[count++] = r;
        }
    }

    fclose(fp);
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
static void apply_rtbh(const char *ip)
{
    printf("[RTBH] Blackholing traffic to/from IP: %s\n", ip);
}

static void apply_acl(const char *ip)
{
    printf("[ACL ] Installing drop rule for IP: %s\n", ip);
}

/* ==============================
   Metrics logging
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

    /* header is not strictly needed; you can add once manually */

    for (int i = 0; i < num_alerts; i++) {
        fprintf(fp,
                "%d,%d,%s,%.3f,%.3f,%.3f,%d,%d,%d,%s\n",
                alerts[i].worker_rank,
                alerts[i].attack_flag,
                alerts[i].suspicious_ip,
                alerts[i].entropy,
                alerts[i].avg_rate,
                alerts[i].spike_score,
                alerts[i].total_packets,
                alerts[i].total_flows,
                global_attack_flag,
                (chosen_ip && chosen_ip[0]) ? chosen_ip : "NONE");
    }

    fclose(fp);
}
