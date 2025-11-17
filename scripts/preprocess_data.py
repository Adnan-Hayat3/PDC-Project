#!/usr/bin/env python3
"""
Data preprocessing script for CIC-DDoS2019 dataset
Partitions traffic data across MPI nodes for distributed processing
"""

import pandas as pd
import numpy as np
import os
import sys
from pathlib import Path

def load_and_clean_dataset(csv_path):
    """Load CSV and clean data"""
    print(f"Loading dataset from {csv_path}...")
    
    try:
        df = pd.read_csv(csv_path, low_memory=False)
        print(f"  Loaded {len(df)} records")
        
        # Remove any unnamed columns
        df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
        
        # Handle infinity values
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Fill NaN with 0
        df = df.fillna(0)
        
        print(f"  After cleaning: {len(df)} records")
        return df
        
    except Exception as e:
        print(f"Error loading dataset: {e}")
        return None

def create_simplified_format(df):
    """Extract key fields for detector"""
    
    # Map column names (handle different CSV formats)
    src_ip_col = None
    dst_ip_col = None
    
    for col in df.columns:
        col_lower = col.strip().lower()
        if 'source' in col_lower and 'ip' in col_lower:
            src_ip_col = col
        if 'destination' in col_lower and 'ip' in col_lower:
            dst_ip_col = col
    
    if src_ip_col is None or dst_ip_col is None:
        print("Could not find IP columns, using defaults...")
        src_ip_col = df.columns[2] if len(df.columns) > 2 else None
        dst_ip_col = df.columns[4] if len(df.columns) > 4 else None
    
    # Extract relevant fields
    simplified = pd.DataFrame()
    
    if src_ip_col:
        simplified['src_ip'] = df[src_ip_col].astype(str)
    else:
        simplified['src_ip'] = '192.168.1.' + (np.random.randint(1, 255, len(df))).astype(str)
    
    if dst_ip_col:
        simplified['dst_ip'] = df[dst_ip_col].astype(str)
    else:
        simplified['dst_ip'] = '10.0.0.' + (np.random.randint(1, 255, len(df))).astype(str)
    
    # Find port columns
    src_port_col = next((c for c in df.columns if 'source' in c.lower() and 'port' in c.lower()), None)
    dst_port_col = next((c for c in df.columns if 'destination' in c.lower() and 'port' in c.lower()), None)
    
    simplified['src_port'] = df[src_port_col].astype(int) if src_port_col else np.random.randint(1024, 65535, len(df))
    simplified['dst_port'] = df[dst_port_col].astype(int) if dst_port_col else np.random.randint(1, 1024, len(df))
    
    # Protocol
    protocol_col = next((c for c in df.columns if 'protocol' in c.lower()), None)
    if protocol_col:
        simplified['protocol'] = df[protocol_col].astype(int)
    else:
        simplified['protocol'] = 17  # UDP default
    
    # Bytes and packets
    bytes_col = next((c for c in df.columns if 'length' in c.lower() and 'fwd' in c.lower()), None)
    simplified['bytes'] = df[bytes_col].astype(int) if bytes_col else np.random.randint(64, 1500, len(df))
    
    packets_col = next((c for c in df.columns if 'total' in c.lower() and 'fwd' in c.lower() and 'packet' in c.lower()), None)
    simplified['packets'] = df[packets_col].astype(int) if packets_col else 1
    
    # Timestamp (use current time + offset)
    import time
    base_time = int(time.time())
    simplified['timestamp'] = base_time + np.arange(len(df))
    
    return simplified

def partition_data_flow_based(df, num_partitions, output_dir):
    """Partition data based on flow (IP pairs)"""
    
    print(f"\nPartitioning data into {num_partitions} partitions (flow-based)...")
    
    # Create flow key
    df['flow_key'] = df['src_ip'] + '-' + df['dst_ip']
    
    # Hash-based partitioning
    df['partition'] = df['flow_key'].apply(lambda x: hash(x) % num_partitions)
    
    os.makedirs(output_dir, exist_ok=True)
    
    for i in range(num_partitions):
        partition_df = df[df['partition'] == i].copy()
        partition_df = partition_df.drop(['flow_key', 'partition'], axis=1)
        
        output_file = os.path.join(output_dir, f'part_{i+1}.csv')
        partition_df.to_csv(output_file, index=False)
        print(f"  Partition {i+1}: {len(partition_df)} records -> {output_file}")
    
    print(f"\nPartitioning complete. Files saved to {output_dir}/")

def generate_dataset_stats(df, label):
    """Generate statistics about the dataset"""
    
    print(f"\n=== Dataset Statistics ({label}) ===")
    print(f"Total records: {len(df)}")
    print(f"Unique source IPs: {df['src_ip'].nunique()}")
    print(f"Unique destination IPs: {df['dst_ip'].nunique()}")
    print(f"Protocol distribution:")
    
    if 'protocol' in df.columns:
        proto_dist = df['protocol'].value_counts()
        for proto, count in proto_dist.items():
            proto_name = "TCP" if proto == 6 else "UDP" if proto == 17 else f"Other({proto})"
            print(f"  {proto_name}: {count} ({100*count/len(df):.1f}%)")
    
    if 'bytes' in df.columns:
        print(f"Average packet size: {df['bytes'].mean():.2f} bytes")
        print(f"Total traffic: {df['bytes'].sum()/1e9:.3f} GB")

def main():
    if len(sys.argv) < 4:
        print("Usage: python preprocess_data.py <input_csv> <num_partitions> <output_dir>")
        print("Example: python preprocess_data.py ../CSV-01-12/CSV-01-12/01-12/DrDoS_UDP.csv 4 ../data")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    num_partitions = int(sys.argv[2])
    output_dir = sys.argv[3]
    
    if not os.path.exists(input_csv):
        print(f"Error: Input file not found: {input_csv}")
        sys.exit(1)
    
    # Load and clean
    df = load_and_clean_dataset(input_csv)
    if df is None:
        sys.exit(1)
    
    # Create simplified format
    simplified_df = create_simplified_format(df)
    
    # Generate stats
    dataset_label = os.path.basename(input_csv).replace('.csv', '')
    generate_dataset_stats(simplified_df, dataset_label)
    
    # Create partition directory
    partition_dir = os.path.join(output_dir, 'partitions')
    
    # Partition data
    partition_data_flow_based(simplified_df, num_partitions, partition_dir)
    
    print("\n✓ Data preprocessing complete!")
    print(f"  Ready for MPI processing with {num_partitions} workers")

if __name__ == "__main__":
    main()
