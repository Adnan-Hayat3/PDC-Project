#!/usr/bin/env python3
"""
Performance Analysis and Visualization Tool
For MPI-based DDoS Detection System
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

# Set plot style
plt.style.use('seaborn-v0_8-darkgrid')

def load_alerts(filepath='results/metrics/alerts.csv'):
    """Load and parse alerts data"""
    try:
        df = pd.read_csv(filepath)
        print(f"Loaded {len(df)} alerts from {filepath}")
        return df
    except FileNotFoundError:
        print(f"Error: {filepath} not found")
        return None

def load_blocking_stats(filepath='results/metrics/blocking.csv'):
    """Load and parse blocking statistics"""
    try:
        df = pd.read_csv(filepath)
        print(f"Loaded {len(df)} blocking records from {filepath}")
        return df
    except FileNotFoundError:
        print(f"Error: {filepath} not found")
        return None

def calculate_accuracy_metrics(df):
    """Calculate precision, recall, F1 score"""
    # Simulate ground truth (in real scenario, load from labeled dataset)
    # For demo purposes, assume attack_flag is correct
    
    tp = len(df[(df['attack_flag'] == 1) & (df['global_attack'] == 1)])
    fp = len(df[(df['attack_flag'] == 1) & (df['global_attack'] == 0)])
    tn = len(df[(df['attack_flag'] == 0) & (df['global_attack'] == 0)])
    fn = len(df[(df['attack_flag'] == 0) & (df['global_attack'] == 1)])
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    return {
        'True Positives': tp,
        'False Positives': fp,
        'True Negatives': tn,
        'False Negatives': fn,
        'Precision': precision,
        'Recall': recall,
        'F1-Score': f1,
        'Accuracy': accuracy,
        'False Positive Rate': fpr
    }

def plot_detection_methods(df, output_dir='results/plots'):
    """Plot detection method effectiveness"""
    os.makedirs(output_dir, exist_ok=True)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    methods = ['entropy_detected', 'cusum_detected', 'ml_detected']
    counts = [df[method].sum() for method in methods]
    labels = ['Entropy', 'CUSUM', 'ML-Based']
    
    bars = ax.bar(labels, counts, color=['#FF6B6B', '#4ECDC4', '#45B7D1'])
    ax.set_ylabel('Number of Detections')
    ax.set_title('Detection Algorithm Comparison')
    ax.set_xlabel('Detection Method')
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/detection_methods.png', dpi=300)
    print(f"Saved detection methods plot to {output_dir}/detection_methods.png")
    plt.close()

def plot_performance_metrics(df, output_dir='results/plots'):
    """Plot performance metrics over workers"""
    os.makedirs(output_dir, exist_ok=True)
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # Processing time per worker
    worker_stats = df.groupby('worker_rank').agg({
        'processing_time_ms': 'mean',
        'total_packets': 'sum',
        'memory_used_kb': 'mean'
    }).reset_index()
    
    # Plot 1: Processing Time
    axes[0, 0].bar(worker_stats['worker_rank'], worker_stats['processing_time_ms'], 
                   color='#FF6B6B')
    axes[0, 0].set_xlabel('Worker Rank')
    axes[0, 0].set_ylabel('Processing Time (ms)')
    axes[0, 0].set_title('Processing Time per Worker')
    axes[0, 0].grid(True, alpha=0.3)
    
    # Plot 2: Packets Processed
    axes[0, 1].bar(worker_stats['worker_rank'], worker_stats['total_packets'], 
                   color='#4ECDC4')
    axes[0, 1].set_xlabel('Worker Rank')
    axes[0, 1].set_ylabel('Total Packets')
    axes[0, 1].set_title('Packets Processed per Worker')
    axes[0, 1].grid(True, alpha=0.3)
    
    # Plot 3: Memory Usage
    axes[1, 0].bar(worker_stats['worker_rank'], worker_stats['memory_used_kb'], 
                   color='#45B7D1')
    axes[1, 0].set_xlabel('Worker Rank')
    axes[1, 0].set_ylabel('Memory (KB)')
    axes[1, 0].set_title('Memory Usage per Worker')
    axes[1, 0].grid(True, alpha=0.3)
    
    # Plot 4: Throughput (packets/ms)
    throughput = worker_stats['total_packets'] / worker_stats['processing_time_ms']
    axes[1, 1].bar(worker_stats['worker_rank'], throughput, color='#95E1D3')
    axes[1, 1].set_xlabel('Worker Rank')
    axes[1, 1].set_ylabel('Throughput (packets/ms)')
    axes[1, 1].set_title('Processing Throughput per Worker')
    axes[1, 1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/performance_metrics.png', dpi=300)
    print(f"Saved performance metrics plot to {output_dir}/performance_metrics.png")
    plt.close()

def plot_feature_analysis(df, output_dir='results/plots'):
    """Plot feature distributions for attack vs normal"""
    os.makedirs(output_dir, exist_ok=True)
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    attack_df = df[df['attack_flag'] == 1]
    normal_df = df[df['attack_flag'] == 0]
    
    # Entropy distribution
    axes[0, 0].hist(attack_df['entropy'], bins=20, alpha=0.6, label='Attack', color='red')
    axes[0, 0].hist(normal_df['entropy'], bins=20, alpha=0.6, label='Normal', color='green')
    axes[0, 0].set_xlabel('Entropy')
    axes[0, 0].set_ylabel('Frequency')
    axes[0, 0].set_title('Entropy Distribution')
    axes[0, 0].legend()
    axes[0, 0].grid(True, alpha=0.3)
    
    # Average Rate distribution
    axes[0, 1].hist(attack_df['avg_rate'], bins=20, alpha=0.6, label='Attack', color='red')
    axes[0, 1].hist(normal_df['avg_rate'], bins=20, alpha=0.6, label='Normal', color='green')
    axes[0, 1].set_xlabel('Average Rate (packets/s)')
    axes[0, 1].set_ylabel('Frequency')
    axes[0, 1].set_title('Packet Rate Distribution')
    axes[0, 1].legend()
    axes[0, 1].grid(True, alpha=0.3)
    
    # Spike Score distribution
    axes[1, 0].hist(attack_df['spike_score'], bins=20, alpha=0.6, label='Attack', color='red')
    axes[1, 0].hist(normal_df['spike_score'], bins=20, alpha=0.6, label='Normal', color='green')
    axes[1, 0].set_xlabel('Spike Score')
    axes[1, 0].set_ylabel('Frequency')
    axes[1, 0].set_title('Traffic Spike Distribution')
    axes[1, 0].legend()
    axes[1, 0].grid(True, alpha=0.3)
    
    # Total Packets distribution
    axes[1, 1].hist(attack_df['total_packets'], bins=20, alpha=0.6, label='Attack', color='red')
    axes[1, 1].hist(normal_df['total_packets'], bins=20, alpha=0.6, label='Normal', color='green')
    axes[1, 1].set_xlabel('Total Packets')
    axes[1, 1].set_ylabel('Frequency')
    axes[1, 1].set_title('Packet Volume Distribution')
    axes[1, 1].legend()
    axes[1, 1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/feature_analysis.png', dpi=300)
    print(f"Saved feature analysis plot to {output_dir}/feature_analysis.png")
    plt.close()

def plot_blocking_efficiency(df, output_dir='results/plots'):
    """Plot blocking effectiveness"""
    if df is None or len(df) == 0:
        print("No blocking data available")
        return
    
    os.makedirs(output_dir, exist_ok=True)
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    
    # Blocking efficiency
    axes[0].bar(['Attack Blocked', 'Legitimate Blocked'], 
                [df['attack_packets_blocked'].mean(), 
                 df['legitimate_packets_blocked'].mean()],
                color=['green', 'red'])
    axes[0].set_ylabel('Packets')
    axes[0].set_title('Blocking Effectiveness')
    axes[0].grid(True, alpha=0.3)
    
    # Efficiency metrics
    metrics = ['Blocking\nEfficiency', 'Collateral\nDamage']
    values = [df['blocking_efficiency'].mean() * 100, 
              df['collateral_damage'].mean() * 100]
    bars = axes[1].bar(metrics, values, color=['#4ECDC4', '#FF6B6B'])
    axes[1].set_ylabel('Percentage (%)')
    axes[1].set_title('Blocking Quality Metrics')
    axes[1].grid(True, alpha=0.3)
    
    # Add percentage labels
    for bar in bars:
        height = bar.get_height()
        axes[1].text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2f}%',
                    ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/blocking_efficiency.png', dpi=300)
    print(f"Saved blocking efficiency plot to {output_dir}/blocking_efficiency.png")
    plt.close()

def generate_report(alerts_df, blocking_df, output_file='results/analysis_report.txt'):
    """Generate comprehensive text report"""
    
    with open(output_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("MPI-BASED DDoS DETECTION SYSTEM - PERFORMANCE ANALYSIS REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        # System Configuration
        f.write("1. SYSTEM CONFIGURATION\n")
        f.write("-" * 70 + "\n")
        num_workers = alerts_df['worker_rank'].nunique()
        f.write(f"Number of Workers: {num_workers}\n")
        f.write(f"Total Alerts Generated: {len(alerts_df)}\n")
        f.write(f"Total Attacks Detected: {alerts_df['attack_flag'].sum()}\n\n")
        
        # Detection Accuracy
        f.write("2. DETECTION ACCURACY METRICS\n")
        f.write("-" * 70 + "\n")
        metrics = calculate_accuracy_metrics(alerts_df)
        for key, value in metrics.items():
            if isinstance(value, float):
                f.write(f"{key:.<30} {value:.4f}\n")
            else:
                f.write(f"{key:.<30} {value}\n")
        f.write("\n")
        
        # Detection Methods
        f.write("3. DETECTION METHOD ANALYSIS\n")
        f.write("-" * 70 + "\n")
        f.write(f"Entropy-based detections: {alerts_df['entropy_detected'].sum()}\n")
        f.write(f"CUSUM detections:         {alerts_df['cusum_detected'].sum()}\n")
        f.write(f"ML-based detections:      {alerts_df['ml_detected'].sum()}\n\n")
        
        # Performance Metrics
        f.write("4. PERFORMANCE METRICS\n")
        f.write("-" * 70 + "\n")
        f.write(f"Average Processing Time:  {alerts_df['processing_time_ms'].mean():.2f} ms\n")
        f.write(f"Total Packets Processed:  {alerts_df['total_packets'].sum()}\n")
        f.write(f"Average Memory Usage:     {alerts_df['memory_used_kb'].mean():.2f} KB\n")
        total_time = alerts_df['processing_time_ms'].sum() / 1000  # seconds
        throughput = alerts_df['total_packets'].sum() / total_time if total_time > 0 else 0
        f.write(f"Throughput:               {throughput:.2f} packets/sec\n\n")
        
        # Blocking Statistics
        if blocking_df is not None and len(blocking_df) > 0:
            f.write("5. BLOCKING EFFECTIVENESS\n")
            f.write("-" * 70 + "\n")
            f.write(f"Attack Packets Blocked:       {blocking_df['attack_packets_blocked'].sum()}\n")
            f.write(f"Legitimate Packets Blocked:   {blocking_df['legitimate_packets_blocked'].sum()}\n")
            f.write(f"Average Blocking Efficiency:  {blocking_df['blocking_efficiency'].mean()*100:.2f}%\n")
            f.write(f"Average Collateral Damage:    {blocking_df['collateral_damage'].mean()*100:.2f}%\n")
            f.write(f"Average Block Time:           {blocking_df['block_time_ms'].mean():.3f} ms\n\n")
        
        # Worker Load Distribution
        f.write("6. WORKER LOAD DISTRIBUTION\n")
        f.write("-" * 70 + "\n")
        worker_stats = alerts_df.groupby('worker_rank').agg({
            'total_packets': 'sum',
            'processing_time_ms': 'mean'
        })
        f.write(f"{'Worker':<10} {'Packets':>15} {'Avg Time (ms)':>20}\n")
        f.write("-" * 70 + "\n")
        for idx, row in worker_stats.iterrows():
            f.write(f"{idx:<10} {int(row['total_packets']):>15} {row['processing_time_ms']:>20.2f}\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 70 + "\n")
    
    print(f"Generated analysis report: {output_file}")

def main():
    """Main analysis function"""
    print("\n" + "="*70)
    print("MPI-BASED DDoS DETECTION SYSTEM - ANALYSIS TOOL")
    print("="*70 + "\n")
    
    # Load data
    alerts_df = load_alerts()
    blocking_df = load_blocking_stats()
    
    if alerts_df is None:
        print("Error: Cannot proceed without alerts data")
        return 1
    
    # Generate visualizations
    print("\nGenerating visualizations...")
    plot_detection_methods(alerts_df)
    plot_performance_metrics(alerts_df)
    plot_feature_analysis(alerts_df)
    plot_blocking_efficiency(blocking_df)
    
    # Generate report
    print("\nGenerating analysis report...")
    generate_report(alerts_df, blocking_df)
    
    # Display summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    metrics = calculate_accuracy_metrics(alerts_df)
    print(f"Precision:  {metrics['Precision']:.4f}")
    print(f"Recall:     {metrics['Recall']:.4f}")
    print(f"F1-Score:   {metrics['F1-Score']:.4f}")
    print(f"Accuracy:   {metrics['Accuracy']:.4f}")
    print(f"FPR:        {metrics['False Positive Rate']:.4f}")
    print("="*70 + "\n")
    
    print("Analysis complete! Check results/plots/ for visualizations.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
