#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "detector.h"

#define MAX_LINE 4096
#define MAX_FIELDS 90

/* Parse CIC-DDoS2019 CSV format and partition data for MPI nodes */

typedef struct {
    char *fields[MAX_FIELDS];
    int field_count;
} CSVRow;

static int parse_csv_line(char *line, CSVRow *row)
{
    row->field_count = 0;
    char *ptr = line;
    int in_quotes = 0;
    char *field_start = ptr;
    
    while (*ptr && row->field_count < MAX_FIELDS) {
        if (*ptr == '"') {
            in_quotes = !in_quotes;
        } else if (*ptr == ',' && !in_quotes) {
            *ptr = '\0';
            row->fields[row->field_count++] = field_start;
            field_start = ptr + 1;
        }
        ptr++;
    }
    
    /* Last field */
    if (field_start < ptr && row->field_count < MAX_FIELDS) {
        row->fields[row->field_count++] = field_start;
    }
    
    return row->field_count;
}

static void trim_whitespace(char *str)
{
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;
    
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

static int parse_timestamp(const char *ts_str)
{
    /* Convert timestamp string to seconds since epoch */
    /* Format: "2018-12-01 12:36:57.674898" */
    int year, month, day, hour, min, sec;
    if (sscanf(ts_str, "%d-%d-%d %d:%d:%d", 
               &year, &month, &day, &hour, &min, &sec) == 6) {
        /* Simple conversion (not accurate for all dates but sufficient) */
        return (year - 1970) * 365 * 24 * 3600 + 
               month * 30 * 24 * 3600 + 
               day * 24 * 3600 + 
               hour * 3600 + min * 60 + sec;
    }
    return 0;
}

int load_cic_ddos_csv(const char *filename, FlowRecord *records, int max_records)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open %s\n", filename);
        return 0;
    }
    
    char line[MAX_LINE];
    CSVRow row;
    int count = 0;
    int header_skipped = 0;
    
    printf("Loading dataset from %s...\n", filename);
    
    while (fgets(line, sizeof(line), fp) && count < max_records) {
        /* Skip header */
        if (!header_skipped) {
            header_skipped = 1;
            continue;
        }
        
        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        if (parse_csv_line(line, &row) < 10) {
            continue;  /* Not enough fields */
        }
        
        FlowRecord r;
        memset(&r, 0, sizeof(r));
        
        /* CIC-DDoS2019 CSV format indices (example):
         * 0: Flow ID
         * 1: Source IP
         * 2: Source Port
         * 3: Destination IP
         * 4: Destination Port
         * 5: Protocol
         * 6: Timestamp
         * 7: Flow Duration
         * 8: Total Fwd Packets
         * 9: Total Backward Packets
         * ... many more fields ...
         * Last field: Label (Benign/Attack type)
         */
        
        /* Extract key fields */
        if (row.field_count > 1) {
            strncpy(r.src_ip, row.fields[1], IP_STR_LEN - 1);
            trim_whitespace(r.src_ip);
        }
        
        if (row.field_count > 3) {
            strncpy(r.dst_ip, row.fields[3], IP_STR_LEN - 1);
            trim_whitespace(r.dst_ip);
        }
        
        if (row.field_count > 2) {
            r.src_port = atoi(row.fields[2]);
        }
        
        if (row.field_count > 4) {
            r.dst_port = atoi(row.fields[4]);
        }
        
        if (row.field_count > 5) {
            r.protocol = atoi(row.fields[5]);
        }
        
        if (row.field_count > 6) {
            r.timestamp = parse_timestamp(row.fields[6]);
        }
        
        /* Estimate bytes from packet counts (if available) */
        if (row.field_count > 8) {
            int fwd_pkts = atoi(row.fields[8]);
            r.packets = fwd_pkts;
            r.bytes = fwd_pkts * 800;  /* Assume ~800 bytes per packet */
        }
        
        records[count++] = r;
        
        if (count % 10000 == 0) {
            printf("  Loaded %d records...\n", count);
        }
    }
    
    fclose(fp);
    printf("Total records loaded: %d\n", count);
    return count;
}

/* Partition dataset into N files for MPI workers */
int partition_dataset(const char *input_file, const char *output_dir, int num_partitions)
{
    FlowRecord *all_records = malloc(sizeof(FlowRecord) * MAX_FLOWS * 10);
    if (!all_records) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    
    int total = load_cic_ddos_csv(input_file, all_records, MAX_FLOWS * 10);
    if (total <= 0) {
        free(all_records);
        return -1;
    }
    
    printf("\nPartitioning %d records into %d partitions...\n", total, num_partitions);
    
    int records_per_partition = (total + num_partitions - 1) / num_partitions;
    
    for (int p = 0; p < num_partitions; p++) {
        char out_path[512];
        snprintf(out_path, sizeof(out_path), "%s/part_%d.csv", output_dir, p + 1);
        
        FILE *fp = fopen(out_path, "w");
        if (!fp) {
            fprintf(stderr, "Cannot create %s\n", out_path);
            continue;
        }
        
        /* Write CSV header */
        fprintf(fp, "src_ip,dst_ip,bytes,timestamp,protocol,src_port,dst_port,packets\n");
        
        int start = p * records_per_partition;
        int end = (p + 1) * records_per_partition;
        if (end > total) end = total;
        
        for (int i = start; i < end; i++) {
            FlowRecord *r = &all_records[i];
            fprintf(fp, "%s,%s,%d,%d,%d,%d,%d,%d\n",
                    r->src_ip, r->dst_ip, r->bytes, r->timestamp,
                    r->protocol, r->src_port, r->dst_port, r->packets);
        }
        
        fclose(fp);
        printf("  Created %s with %d records\n", out_path, end - start);
    }
    
    free(all_records);
    printf("Partitioning complete.\n");
    return 0;
}

/* Main function for standalone preprocessing */
int main(int argc, char **argv)
{
    if (argc < 4) {
        printf("Usage: %s <input_csv> <output_dir> <num_partitions>\n", argv[0]);
        printf("Example: %s DrDoS_UDP.csv data/partitions 4\n", argv[0]);
        return 1;
    }
    
    const char *input_file = argv[1];
    const char *output_dir = argv[2];
    int num_partitions = atoi(argv[3]);
    
    if (num_partitions < 1 || num_partitions > 100) {
        fprintf(stderr, "Invalid number of partitions: %d\n", num_partitions);
        return 1;
    }
    
    return partition_dataset(input_file, output_dir, num_partitions);
}
