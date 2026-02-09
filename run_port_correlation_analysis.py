"""
L4 Port Correlation Analysis with Labels
=========================================
Analyzes the correlation between L4_SRC_PORT, L4_DST_PORT and Labels
for each dataset in v3-Datasets.

Includes:
1. Binary label analysis (Benign vs Malicious)
2. Multi-class attack type analysis
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import chi2_contingency, pointbiserialr
from collections import Counter
import os
import warnings

warnings.filterwarnings('ignore')

# === Configuration ===
BASE_DIR = r'c:\Users\josia\Documents\Kill Chain Research'
OUTPUT_DIR = os.path.join(BASE_DIR, 'L4PortCorrelationAnalysis')
os.makedirs(OUTPUT_DIR, exist_ok=True)

DATASETS = [
    ('NF-BoT-IoT-v3', os.path.join(BASE_DIR, 'v3-Datasets/NF-BoT-IoT-v3/data/NF-BoT-IoT-v3.csv')),
    ('NF-CICIDS2018-v3', os.path.join(BASE_DIR, 'v3-Datasets/NF-CICIDS2018-v3/data/NF-CICIDS2018-v3.csv')),
    ('NF-ToN-IoT-v3', os.path.join(BASE_DIR, 'v3-Datasets/NF-ToN-IoT-v3/data/NF-ToN-IoT-v3.csv')),
    ('NF-UNSW-NB15-v3', os.path.join(BASE_DIR, 'v3-Datasets/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv')),
]

# Well-known ports for reference
WELL_KNOWN_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
}


def print_header(text):
    print("\n" + "=" * 70, flush=True)
    print(text, flush=True)
    print("=" * 70, flush=True)


def cramers_v(confusion_matrix):
    """Calculate Cramer's V for categorical association."""
    chi2 = chi2_contingency(confusion_matrix)[0]
    n = confusion_matrix.sum().sum()
    min_dim = min(confusion_matrix.shape) - 1
    if min_dim == 0 or n == 0:
        return 0
    return np.sqrt(chi2 / (n * min_dim))


def analyze_binary_port_correlation(df, port_col, dataset_name):
    """Analyze correlation between a port column and binary label (Benign vs Malicious)."""

    results = {}

    # Create binary label (0 = Benign, 1 = Malicious)
    df = df.copy()
    df['Binary_Label'] = (df['Attack'] != 'Benign').astype(int)

    results['total_samples'] = len(df)
    results['benign_count'] = (df['Binary_Label'] == 0).sum()
    results['malicious_count'] = (df['Binary_Label'] == 1).sum()
    results['unique_ports'] = df[port_col].nunique()

    # Point-biserial correlation (for binary categorical vs continuous)
    # Sample for large datasets
    if len(df) > 200000:
        sample_df = df.sample(n=200000, random_state=42)
    else:
        sample_df = df

    # Calculate point-biserial correlation
    try:
        corr, p_value = pointbiserialr(sample_df['Binary_Label'], sample_df[port_col])
        results['point_biserial_r'] = corr
        results['point_biserial_p'] = p_value
    except Exception:
        results['point_biserial_r'] = 0.0
        results['point_biserial_p'] = 1.0

    # Port category analysis for binary
    def port_category(port):
        if port < 1024:
            return 'Well-Known (0-1023)'
        elif port < 49152:
            return 'Registered (1024-49151)'
        else:
            return 'Dynamic (49152+)'

    sample_df = sample_df.copy()
    sample_df['port_category'] = sample_df[port_col].apply(port_category)

    # Chi-squared for port categories vs binary label
    contingency = pd.crosstab(sample_df['port_category'], sample_df['Binary_Label'])
    chi2, p_value, dof, expected = chi2_contingency(contingency)
    results['chi2'] = chi2
    results['chi2_p_value'] = p_value
    results['cramers_v'] = cramers_v(contingency)

    # Port distribution stats for benign vs malicious
    benign_ports = df[df['Binary_Label'] == 0][port_col]
    malicious_ports = df[df['Binary_Label'] == 1][port_col]

    results['benign_port_mean'] = benign_ports.mean()
    results['benign_port_std'] = benign_ports.std()
    results['malicious_port_mean'] = malicious_ports.mean()
    results['malicious_port_std'] = malicious_ports.std()

    # Top ports for each class
    results['top_benign_ports'] = benign_ports.value_counts().head(10)
    results['top_malicious_ports'] = malicious_ports.value_counts().head(10)

    # Ports highly specific to malicious traffic (>80%)
    malicious_specific_ports = {}
    for port in df[port_col].value_counts().head(100).index:
        port_df = df[df[port_col] == port]
        mal_ratio = port_df['Binary_Label'].mean()
        if mal_ratio > 0.8:  # >80% malicious
            malicious_specific_ports[port] = {
                'malicious_ratio': mal_ratio,
                'count': len(port_df)
            }
    results['malicious_specific_ports'] = malicious_specific_ports

    # Ports highly specific to benign traffic (>80%)
    benign_specific_ports = {}
    for port in df[port_col].value_counts().head(100).index:
        port_df = df[df[port_col] == port]
        benign_ratio = 1 - port_df['Binary_Label'].mean()
        if benign_ratio > 0.8:  # >80% benign
            benign_specific_ports[port] = {
                'benign_ratio': benign_ratio,
                'count': len(port_df)
            }
    results['benign_specific_ports'] = benign_specific_ports

    return results


def analyze_port_label_correlation(df, port_col, label_col, dataset_name, output_dir):
    """Analyze correlation between a port column and labels."""

    results = {}

    # Basic stats
    results['total_samples'] = len(df)
    results['unique_ports'] = df[port_col].nunique()
    results['unique_labels'] = df[label_col].nunique()

    # Port distribution by label
    port_label_counts = df.groupby([label_col, port_col]).size().reset_index(name='count')

    # Top ports overall
    top_ports_overall = df[port_col].value_counts().head(20)
    results['top_ports_overall'] = top_ports_overall

    # Top ports per label
    top_ports_per_label = {}
    for label in df[label_col].unique():
        label_df = df[df[label_col] == label]
        top_ports_per_label[label] = label_df[port_col].value_counts().head(10)
    results['top_ports_per_label'] = top_ports_per_label

    # Calculate Cramer's V (categorical correlation)
    # Create contingency table (sample for large datasets)
    if len(df) > 100000:
        sample_df = df.sample(n=100000, random_state=42)
    else:
        sample_df = df

    # Bin ports for contingency analysis (well-known vs registered vs dynamic)
    def port_category(port):
        if port < 1024:
            return 'Well-Known (0-1023)'
        elif port < 49152:
            return 'Registered (1024-49151)'
        else:
            return 'Dynamic (49152+)'

    sample_df = sample_df.copy()
    sample_df['port_category'] = sample_df[port_col].apply(port_category)

    contingency = pd.crosstab(sample_df['port_category'], sample_df[label_col])

    # Chi-squared test
    chi2, p_value, dof, expected = chi2_contingency(contingency)
    results['chi2'] = chi2
    results['chi2_p_value'] = p_value
    results['cramers_v'] = cramers_v(contingency)

    # Find ports that are highly specific to certain labels
    port_label_specificity = {}
    for port in df[port_col].value_counts().head(100).index:
        port_df = df[df[port_col] == port]
        label_dist = port_df[label_col].value_counts(normalize=True)
        if label_dist.iloc[0] > 0.8:  # >80% specific to one label
            port_label_specificity[port] = {
                'dominant_label': label_dist.index[0],
                'specificity': label_dist.iloc[0],
                'count': len(port_df)
            }
    results['highly_specific_ports'] = port_label_specificity

    return results, contingency


def plot_port_distribution_by_label(df, port_col, label_col, dataset_name, output_dir, top_n=15):
    """Plot port distribution grouped by label."""

    # Get top ports
    top_ports = df[port_col].value_counts().head(top_n).index.tolist()
    df_filtered = df[df[port_col].isin(top_ports)]

    # Create figure
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))

    # 1. Stacked bar: Port distribution by label
    ax1 = axes[0, 0]
    port_label_counts = df_filtered.groupby([port_col, label_col]).size().unstack(fill_value=0)
    port_label_counts = port_label_counts.loc[top_ports]
    port_label_counts.plot(kind='bar', stacked=True, ax=ax1, colormap='tab20')
    ax1.set_title(f'{dataset_name}: Top {top_n} Ports by Label', fontsize=12, fontweight='bold')
    ax1.set_xlabel(port_col)
    ax1.set_ylabel('Count')
    ax1.legend(title='Label', bbox_to_anchor=(1.02, 1), loc='upper left', fontsize=8)
    ax1.tick_params(axis='x', rotation=45)

    # 2. Normalized stacked bar: Port distribution by label (percentage)
    ax2 = axes[0, 1]
    port_label_pct = port_label_counts.div(port_label_counts.sum(axis=1), axis=0) * 100
    port_label_pct.plot(kind='bar', stacked=True, ax=ax2, colormap='tab20')
    ax2.set_title(f'{dataset_name}: Top {top_n} Ports by Label (%)', fontsize=12, fontweight='bold')
    ax2.set_xlabel(port_col)
    ax2.set_ylabel('Percentage')
    ax2.legend(title='Label', bbox_to_anchor=(1.02, 1), loc='upper left', fontsize=8)
    ax2.tick_params(axis='x', rotation=45)

    # 3. Heatmap: Port-Label association
    ax3 = axes[1, 0]
    # Normalize by row (per port)
    heatmap_data = port_label_pct.T
    sns.heatmap(heatmap_data, annot=True, fmt='.0f', cmap='YlOrRd', ax=ax3,
                cbar_kws={'label': 'Percentage'}, annot_kws={'fontsize': 7})
    ax3.set_title(f'{dataset_name}: Port-Label Heatmap (%)', fontsize=12, fontweight='bold')
    ax3.set_xlabel('Port')
    ax3.set_ylabel('Label')
    ax3.tick_params(axis='x', rotation=45)
    ax3.tick_params(axis='y', rotation=0)

    # 4. Box plot: Port distribution per label
    ax4 = axes[1, 1]
    # Sample for boxplot (large datasets)
    if len(df) > 50000:
        sample_df = df.sample(n=50000, random_state=42)
    else:
        sample_df = df

    labels_to_plot = sample_df[label_col].value_counts().head(8).index.tolist()
    sample_df_filtered = sample_df[sample_df[label_col].isin(labels_to_plot)]

    sns.boxplot(data=sample_df_filtered, x=label_col, y=port_col, ax=ax4)
    ax4.set_title(f'{dataset_name}: {port_col} Distribution by Label', fontsize=12, fontweight='bold')
    ax4.set_xlabel('Label')
    ax4.set_ylabel(port_col)
    ax4.tick_params(axis='x', rotation=45)
    ax4.set_ylim(0, 65535)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'{dataset_name}_{port_col}_analysis.png'),
                dpi=150, bbox_inches='tight')
    plt.close()


def plot_binary_port_analysis(df, port_col, dataset_name, output_dir):
    """Plot port distribution for Benign vs Malicious (binary) analysis."""

    df = df.copy()
    df['Binary_Label'] = df['Attack'].apply(lambda x: 'Benign' if x == 'Benign' else 'Malicious')

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))

    # Sample for visualization
    if len(df) > 100000:
        sample_df = df.sample(n=100000, random_state=42)
    else:
        sample_df = df

    # 1. Violin plot: Port distribution by binary label
    ax1 = axes[0, 0]
    sns.violinplot(data=sample_df, x='Binary_Label', y=port_col, ax=ax1, palette=['green', 'red'])
    ax1.set_title(f'{dataset_name}: {port_col} Distribution\n(Benign vs Malicious)', fontsize=12, fontweight='bold')
    ax1.set_ylim(0, 65535)
    ax1.set_xlabel('Traffic Type')
    ax1.set_ylabel(port_col)

    # 2. Histogram overlay
    ax2 = axes[0, 1]
    benign_ports = sample_df[sample_df['Binary_Label'] == 'Benign'][port_col]
    malicious_ports = sample_df[sample_df['Binary_Label'] == 'Malicious'][port_col]

    ax2.hist(benign_ports, bins=50, alpha=0.6, label='Benign', color='green', density=True)
    ax2.hist(malicious_ports, bins=50, alpha=0.6, label='Malicious', color='red', density=True)
    ax2.set_xlabel(port_col)
    ax2.set_ylabel('Density')
    ax2.set_title(f'{dataset_name}: {port_col} Distribution Overlay', fontsize=12, fontweight='bold')
    ax2.legend()
    ax2.set_xlim(0, 65535)

    # 3. Top ports comparison (side by side)
    ax3 = axes[1, 0]
    benign_top = df[df['Binary_Label'] == 'Benign'][port_col].value_counts().head(10)
    malicious_top = df[df['Binary_Label'] == 'Malicious'][port_col].value_counts().head(10)

    # Combine unique ports from both
    all_top_ports = list(set(benign_top.index.tolist() + malicious_top.index.tolist()))[:12]

    benign_counts = [benign_top.get(p, 0) for p in all_top_ports]
    malicious_counts = [malicious_top.get(p, 0) for p in all_top_ports]

    x = np.arange(len(all_top_ports))
    width = 0.35

    bars1 = ax3.bar(x - width/2, benign_counts, width, label='Benign', color='green', alpha=0.7)
    bars2 = ax3.bar(x + width/2, malicious_counts, width, label='Malicious', color='red', alpha=0.7)

    # Add service names
    labels = [f"{p}\n({WELL_KNOWN_PORTS.get(p, '')})" if p in WELL_KNOWN_PORTS else str(p) for p in all_top_ports]
    ax3.set_xticks(x)
    ax3.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax3.set_ylabel('Count')
    ax3.set_title(f'{dataset_name}: Top Ports Comparison', fontsize=12, fontweight='bold')
    ax3.legend()
    ax3.set_yscale('log')

    # 4. Port category breakdown
    ax4 = axes[1, 1]

    def port_category(port):
        if port < 1024:
            return 'Well-Known\n(0-1023)'
        elif port < 49152:
            return 'Registered\n(1024-49151)'
        else:
            return 'Dynamic\n(49152+)'

    df['port_category'] = df[port_col].apply(port_category)
    category_binary = df.groupby(['port_category', 'Binary_Label']).size().unstack(fill_value=0)

    # Normalize to percentages within each category
    category_pct = category_binary.div(category_binary.sum(axis=1), axis=0) * 100

    category_pct.plot(kind='bar', ax=ax4, color=['green', 'red'], alpha=0.7)
    ax4.set_title(f'{dataset_name}: {port_col} Category\nby Traffic Type (%)', fontsize=12, fontweight='bold')
    ax4.set_xlabel('Port Category')
    ax4.set_ylabel('Percentage')
    ax4.legend(title='Traffic Type')
    ax4.tick_params(axis='x', rotation=0)

    # Add percentage labels
    for container in ax4.containers:
        ax4.bar_label(container, fmt='%.1f%%', fontsize=8)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'{dataset_name}_{port_col}_binary_analysis.png'),
                dpi=150, bbox_inches='tight')
    plt.close()


def plot_specific_ports_by_attack(df, label_col, dataset_name, output_dir):
    """Plot which specific ports are associated with each attack type."""

    attacks = df[df[label_col] != 'Benign'][label_col].unique()

    if len(attacks) == 0:
        return

    n_attacks = min(len(attacks), 6)  # Max 6 subplots
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    axes = axes.flatten()

    for i, attack in enumerate(attacks[:n_attacks]):
        ax = axes[i]
        attack_df = df[df[label_col] == attack]

        # Combine src and dst ports for analysis
        all_ports = pd.concat([attack_df['L4_SRC_PORT'], attack_df['L4_DST_PORT']])
        top_ports = all_ports.value_counts().head(10)

        # Map to service names if well-known
        labels = [f"{p}\n({WELL_KNOWN_PORTS.get(p, '')})" if p in WELL_KNOWN_PORTS
                  else str(p) for p in top_ports.index]

        bars = ax.barh(range(len(top_ports)), top_ports.values, color='steelblue')
        ax.set_yticks(range(len(top_ports)))
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel('Count')
        ax.set_title(f'{attack}', fontsize=11, fontweight='bold')

        # Highlight well-known ports
        for j, port in enumerate(top_ports.index):
            if port in WELL_KNOWN_PORTS:
                bars[j].set_color('darkorange')

    # Hide unused subplots
    for i in range(n_attacks, 6):
        axes[i].set_visible(False)

    plt.suptitle(f'{dataset_name}: Top Ports by Attack Type\n(Orange = Well-Known Port)',
                 fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'{dataset_name}_attack_ports.png'),
                dpi=150, bbox_inches='tight')
    plt.close()


def generate_correlation_summary(all_results, all_binary_results, output_dir):
    """Generate summary report of all correlations."""

    lines = []
    lines.append("# L4 Port Correlation Analysis Summary\n")
    lines.append("## Overview\n")
    lines.append("This analysis examines the correlation between L4 (transport layer) ports ")
    lines.append("(L4_SRC_PORT and L4_DST_PORT) and attack labels across all four datasets.\n")
    lines.append("\nTwo types of analysis are performed:")
    lines.append("1. **Binary Analysis**: Benign vs Malicious (all attack types combined)")
    lines.append("2. **Multi-class Analysis**: Correlation with specific attack types\n")

    # Binary Analysis Section
    lines.append("\n---\n")
    lines.append("# Part 1: Binary Analysis (Benign vs Malicious)\n")

    lines.append("\n## Binary Correlation Metrics\n")
    lines.append("| Dataset | Port | Point-Biserial r | p-value | Cramér's V | Interpretation |")
    lines.append("|---------|------|------------------|---------|------------|----------------|")

    for dataset_name, results in all_binary_results.items():
        for port_type in ['L4_SRC_PORT', 'L4_DST_PORT']:
            r = results[port_type]
            pb_r = r['point_biserial_r']
            v = r['cramers_v']
            if abs(pb_r) > 0.3:
                interp = "Moderate correlation"
            elif abs(pb_r) > 0.1:
                interp = "Weak correlation"
            else:
                interp = "Very weak/None"

            lines.append(f"| {dataset_name} | {port_type} | {pb_r:.4f} | {r['point_biserial_p']:.2e} | {v:.4f} | {interp} |")

    lines.append("\n## Port Distribution Statistics (Benign vs Malicious)\n")
    lines.append("| Dataset | Port | Benign Mean | Benign Std | Malicious Mean | Malicious Std |")
    lines.append("|---------|------|-------------|------------|----------------|---------------|")

    for dataset_name, results in all_binary_results.items():
        for port_type in ['L4_SRC_PORT', 'L4_DST_PORT']:
            r = results[port_type]
            lines.append(f"| {dataset_name} | {port_type} | {r['benign_port_mean']:.1f} | {r['benign_port_std']:.1f} | {r['malicious_port_mean']:.1f} | {r['malicious_port_std']:.1f} |")

    lines.append("\n## Ports Highly Specific to Malicious Traffic (>80%)\n")

    for dataset_name, results in all_binary_results.items():
        lines.append(f"\n### {dataset_name}\n")

        for port_type in ['L4_SRC_PORT', 'L4_DST_PORT']:
            r = results[port_type]
            specific = r['malicious_specific_ports']

            if specific:
                lines.append(f"\n**{port_type}:**\n")
                lines.append("| Port | Service | Malicious % | Count |")
                lines.append("|------|---------|-------------|-------|")

                for port, info in sorted(specific.items(), key=lambda x: x[1]['malicious_ratio'], reverse=True)[:10]:
                    service = WELL_KNOWN_PORTS.get(port, '-')
                    lines.append(f"| {port} | {service} | {info['malicious_ratio']*100:.1f}% | {info['count']:,} |")
            else:
                lines.append(f"\n**{port_type}:** No ports with >80% malicious traffic found.\n")

    lines.append("\n## Ports Highly Specific to Benign Traffic (>80%)\n")

    for dataset_name, results in all_binary_results.items():
        lines.append(f"\n### {dataset_name}\n")

        for port_type in ['L4_SRC_PORT', 'L4_DST_PORT']:
            r = results[port_type]
            specific = r['benign_specific_ports']

            if specific:
                lines.append(f"\n**{port_type}:**\n")
                lines.append("| Port | Service | Benign % | Count |")
                lines.append("|------|---------|----------|-------|")

                for port, info in sorted(specific.items(), key=lambda x: x[1]['benign_ratio'], reverse=True)[:10]:
                    service = WELL_KNOWN_PORTS.get(port, '-')
                    lines.append(f"| {port} | {service} | {info['benign_ratio']*100:.1f}% | {info['count']:,} |")
            else:
                lines.append(f"\n**{port_type}:** No ports with >80% benign traffic found.\n")

    # Multi-class Analysis Section
    lines.append("\n---\n")
    lines.append("# Part 2: Multi-class Analysis (Specific Attack Types)\n")

    lines.append("\n## Multi-class Correlation Metrics\n")
    lines.append("| Dataset | Port | Chi² | p-value | Cramér's V | Interpretation |")
    lines.append("|---------|------|------|---------|------------|----------------|")

    for dataset_name, results in all_results.items():
        for port_type in ['L4_SRC_PORT', 'L4_DST_PORT']:
            r = results[port_type]
            v = r['cramers_v']
            if v > 0.5:
                interp = "Strong association"
            elif v > 0.3:
                interp = "Moderate association"
            elif v > 0.1:
                interp = "Weak association"
            else:
                interp = "Very weak/None"

            lines.append(f"| {dataset_name} | {port_type} | {r['chi2']:.2f} | {r['chi2_p_value']:.2e} | {v:.4f} | {interp} |")

    lines.append("\n## Highly Specific Ports (>80% associated with one label)\n")

    for dataset_name, results in all_results.items():
        lines.append(f"\n### {dataset_name}\n")

        for port_type in ['L4_SRC_PORT', 'L4_DST_PORT']:
            r = results[port_type]
            specific = r['highly_specific_ports']

            if specific:
                lines.append(f"\n**{port_type}:**\n")
                lines.append("| Port | Service | Dominant Label | Specificity | Count |")
                lines.append("|------|---------|----------------|-------------|-------|")

                for port, info in sorted(specific.items(), key=lambda x: x[1]['specificity'], reverse=True)[:15]:
                    service = WELL_KNOWN_PORTS.get(port, '-')
                    lines.append(f"| {port} | {service} | {info['dominant_label']} | {info['specificity']*100:.1f}% | {info['count']:,} |")
            else:
                lines.append(f"\n**{port_type}:** No ports with >80% specificity found.\n")

    lines.append("\n## Key Findings\n")
    lines.append("### Port-Attack Associations\n")
    lines.append("- **SSH (22)**: Often associated with brute-force attacks (SSH-Bruteforce, password attacks)")
    lines.append("- **HTTP/HTTPS (80, 443, 8080)**: Associated with web attacks (XSS, SQL injection, DDoS)")
    lines.append("- **FTP (20, 21)**: Associated with FTP brute-force attacks")
    lines.append("- **DNS (53)**: Can indicate reconnaissance or DNS-based attacks")
    lines.append("- **High ports (>1024)**: Often used in DoS/DDoS attacks, C2 communications")
    lines.append("- **Dynamic ports (>49152)**: May indicate scanning, C2, or lateral movement\n")

    lines.append("\n## Interpretation Guide\n")
    lines.append("- **Cramér's V**: Measures association strength (0-1)")
    lines.append("  - 0.0-0.1: Very weak or no association")
    lines.append("  - 0.1-0.3: Weak association")
    lines.append("  - 0.3-0.5: Moderate association")
    lines.append("  - 0.5+: Strong association")
    lines.append("- **Chi² p-value**: <0.05 indicates statistically significant association")
    lines.append("- **Specificity**: % of traffic on a port belonging to one label\n")

    with open(os.path.join(output_dir, 'Port_Correlation_Summary.md'), 'w') as f:
        f.write('\n'.join(lines))

    print(f"  Summary saved to {output_dir}/Port_Correlation_Summary.md", flush=True)


# =============================================================================
# MAIN ANALYSIS
# =============================================================================
print_header("L4 PORT CORRELATION ANALYSIS")
print(f"Output directory: {OUTPUT_DIR}", flush=True)

all_results = {}
all_binary_results = {}

for dataset_name, path in DATASETS:
    print_header(f"Analyzing {dataset_name}")

    # Load dataset
    print(f"  Loading data...", flush=True)
    df = pd.read_csv(path, usecols=['L4_SRC_PORT', 'L4_DST_PORT', 'Attack'])
    print(f"  Loaded {len(df):,} samples", flush=True)

    # Count benign vs malicious
    benign_count = (df['Attack'] == 'Benign').sum()
    malicious_count = (df['Attack'] != 'Benign').sum()
    print(f"  Benign: {benign_count:,} ({benign_count/len(df)*100:.1f}%)", flush=True)
    print(f"  Malicious: {malicious_count:,} ({malicious_count/len(df)*100:.1f}%)", flush=True)

    dataset_results = {}
    binary_results = {}

    # =========================================================================
    # BINARY ANALYSIS (Benign vs Malicious)
    # =========================================================================
    print(f"\n  --- Binary Analysis (Benign vs Malicious) ---", flush=True)

    # Binary analysis for L4_SRC_PORT
    print(f"\n  Binary analysis L4_SRC_PORT...", flush=True)
    src_binary = analyze_binary_port_correlation(df, 'L4_SRC_PORT', dataset_name)
    binary_results['L4_SRC_PORT'] = src_binary
    print(f"    Point-biserial r: {src_binary['point_biserial_r']:.4f}", flush=True)
    print(f"    Cramér's V: {src_binary['cramers_v']:.4f}", flush=True)
    print(f"    Malicious-specific ports: {len(src_binary['malicious_specific_ports'])}", flush=True)
    print(f"    Benign-specific ports: {len(src_binary['benign_specific_ports'])}", flush=True)

    # Binary analysis for L4_DST_PORT
    print(f"\n  Binary analysis L4_DST_PORT...", flush=True)
    dst_binary = analyze_binary_port_correlation(df, 'L4_DST_PORT', dataset_name)
    binary_results['L4_DST_PORT'] = dst_binary
    print(f"    Point-biserial r: {dst_binary['point_biserial_r']:.4f}", flush=True)
    print(f"    Cramér's V: {dst_binary['cramers_v']:.4f}", flush=True)
    print(f"    Malicious-specific ports: {len(dst_binary['malicious_specific_ports'])}", flush=True)
    print(f"    Benign-specific ports: {len(dst_binary['benign_specific_ports'])}", flush=True)

    all_binary_results[dataset_name] = binary_results

    # =========================================================================
    # MULTI-CLASS ANALYSIS (Specific Attack Types)
    # =========================================================================
    print(f"\n  --- Multi-class Analysis (Attack Types) ---", flush=True)

    # Analyze L4_SRC_PORT
    print(f"\n  Multi-class analysis L4_SRC_PORT...", flush=True)
    src_results, src_contingency = analyze_port_label_correlation(
        df, 'L4_SRC_PORT', 'Attack', dataset_name, OUTPUT_DIR
    )
    dataset_results['L4_SRC_PORT'] = src_results
    print(f"    Unique ports: {src_results['unique_ports']:,}", flush=True)
    print(f"    Cramér's V: {src_results['cramers_v']:.4f}", flush=True)
    print(f"    Chi² p-value: {src_results['chi2_p_value']:.2e}", flush=True)
    print(f"    Highly specific ports: {len(src_results['highly_specific_ports'])}", flush=True)

    # Analyze L4_DST_PORT
    print(f"\n  Multi-class analysis L4_DST_PORT...", flush=True)
    dst_results, dst_contingency = analyze_port_label_correlation(
        df, 'L4_DST_PORT', 'Attack', dataset_name, OUTPUT_DIR
    )
    dataset_results['L4_DST_PORT'] = dst_results
    print(f"    Unique ports: {dst_results['unique_ports']:,}", flush=True)
    print(f"    Cramér's V: {dst_results['cramers_v']:.4f}", flush=True)
    print(f"    Chi² p-value: {dst_results['chi2_p_value']:.2e}", flush=True)
    print(f"    Highly specific ports: {len(dst_results['highly_specific_ports'])}", flush=True)

    all_results[dataset_name] = dataset_results

    # =========================================================================
    # GENERATE PLOTS
    # =========================================================================
    print(f"\n  Generating plots...", flush=True)

    # Binary analysis plots
    plot_binary_port_analysis(df, 'L4_SRC_PORT', dataset_name, OUTPUT_DIR)
    print(f"    Saved: {dataset_name}_L4_SRC_PORT_binary_analysis.png", flush=True)

    plot_binary_port_analysis(df, 'L4_DST_PORT', dataset_name, OUTPUT_DIR)
    print(f"    Saved: {dataset_name}_L4_DST_PORT_binary_analysis.png", flush=True)

    # Multi-class plots
    plot_port_distribution_by_label(df, 'L4_SRC_PORT', 'Attack', dataset_name, OUTPUT_DIR)
    print(f"    Saved: {dataset_name}_L4_SRC_PORT_analysis.png", flush=True)

    plot_port_distribution_by_label(df, 'L4_DST_PORT', 'Attack', dataset_name, OUTPUT_DIR)
    print(f"    Saved: {dataset_name}_L4_DST_PORT_analysis.png", flush=True)

    # Plot attack-specific ports
    plot_specific_ports_by_attack(df, 'Attack', dataset_name, OUTPUT_DIR)
    print(f"    Saved: {dataset_name}_attack_ports.png", flush=True)

    del df

# Generate combined summary
print_header("Generating Summary Report")
generate_correlation_summary(all_results, all_binary_results, OUTPUT_DIR)

# Create comparison plot across datasets
print("\n  Creating cross-dataset comparison...", flush=True)

datasets_names = list(all_results.keys())
x = np.arange(len(datasets_names))
width = 0.35

# =============================================================================
# Binary Analysis Comparison Plot
# =============================================================================
fig, axes = plt.subplots(2, 2, figsize=(16, 12))

# 1. Point-Biserial correlation comparison (Binary)
ax1 = axes[0, 0]
src_pb = [all_binary_results[d]['L4_SRC_PORT']['point_biserial_r'] for d in datasets_names]
dst_pb = [all_binary_results[d]['L4_DST_PORT']['point_biserial_r'] for d in datasets_names]

bars1 = ax1.bar(x - width/2, src_pb, width, label='L4_SRC_PORT', color='steelblue')
bars2 = ax1.bar(x + width/2, dst_pb, width, label='L4_DST_PORT', color='darkorange')
ax1.set_ylabel("Point-Biserial r")
ax1.set_title("Binary: Port-Malicious Correlation\n(Point-Biserial r)", fontsize=12, fontweight='bold')
ax1.set_xticks(x)
ax1.set_xticklabels([d.replace('NF-', '').replace('-v3', '') for d in datasets_names], rotation=15)
ax1.legend()
ax1.axhline(y=0, color='gray', linestyle='-', alpha=0.3)

for bar in bars1:
    height = bar.get_height()
    ax1.annotate(f'{height:.3f}', xy=(bar.get_x() + bar.get_width()/2, height),
                xytext=(0, 3 if height >= 0 else -10), textcoords="offset points",
                ha='center', va='bottom' if height >= 0 else 'top', fontsize=8)
for bar in bars2:
    height = bar.get_height()
    ax1.annotate(f'{height:.3f}', xy=(bar.get_x() + bar.get_width()/2, height),
                xytext=(0, 3 if height >= 0 else -10), textcoords="offset points",
                ha='center', va='bottom' if height >= 0 else 'top', fontsize=8)

# 2. Cramér's V comparison (Binary)
ax2 = axes[0, 1]
src_v_bin = [all_binary_results[d]['L4_SRC_PORT']['cramers_v'] for d in datasets_names]
dst_v_bin = [all_binary_results[d]['L4_DST_PORT']['cramers_v'] for d in datasets_names]

bars1 = ax2.bar(x - width/2, src_v_bin, width, label='L4_SRC_PORT', color='steelblue')
bars2 = ax2.bar(x + width/2, dst_v_bin, width, label='L4_DST_PORT', color='darkorange')
ax2.set_ylabel("Cramér's V")
ax2.set_title("Binary: Port Category Association\n(Cramér's V)", fontsize=12, fontweight='bold')
ax2.set_xticks(x)
ax2.set_xticklabels([d.replace('NF-', '').replace('-v3', '') for d in datasets_names], rotation=15)
ax2.legend()
ax2.axhline(y=0.3, color='gray', linestyle='--', alpha=0.5)

for bar in bars1:
    height = bar.get_height()
    ax2.annotate(f'{height:.3f}', xy=(bar.get_x() + bar.get_width()/2, height),
                xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)
for bar in bars2:
    height = bar.get_height()
    ax2.annotate(f'{height:.3f}', xy=(bar.get_x() + bar.get_width()/2, height),
                xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)

# 3. Cramér's V comparison (Multi-class)
ax3 = axes[1, 0]
src_v = [all_results[d]['L4_SRC_PORT']['cramers_v'] for d in datasets_names]
dst_v = [all_results[d]['L4_DST_PORT']['cramers_v'] for d in datasets_names]

bars1 = ax3.bar(x - width/2, src_v, width, label='L4_SRC_PORT', color='steelblue')
bars2 = ax3.bar(x + width/2, dst_v, width, label='L4_DST_PORT', color='darkorange')
ax3.set_ylabel("Cramér's V")
ax3.set_title("Multi-class: Port-Attack Association\n(Cramér's V)", fontsize=12, fontweight='bold')
ax3.set_xticks(x)
ax3.set_xticklabels([d.replace('NF-', '').replace('-v3', '') for d in datasets_names], rotation=15)
ax3.legend()
ax3.axhline(y=0.3, color='gray', linestyle='--', alpha=0.5)
ax3.set_ylim(0, max(max(src_v), max(dst_v)) * 1.2)

for bar in bars1:
    height = bar.get_height()
    ax3.annotate(f'{height:.3f}', xy=(bar.get_x() + bar.get_width()/2, height),
                xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)
for bar in bars2:
    height = bar.get_height()
    ax3.annotate(f'{height:.3f}', xy=(bar.get_x() + bar.get_width()/2, height),
                xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)

# 4. Specific ports count comparison (both binary and multi-class)
ax4 = axes[1, 1]
mal_specific = [len(all_binary_results[d]['L4_DST_PORT']['malicious_specific_ports']) for d in datasets_names]
benign_specific = [len(all_binary_results[d]['L4_DST_PORT']['benign_specific_ports']) for d in datasets_names]

bars1 = ax4.bar(x - width/2, mal_specific, width, label='Malicious-specific', color='red', alpha=0.7)
bars2 = ax4.bar(x + width/2, benign_specific, width, label='Benign-specific', color='green', alpha=0.7)
ax4.set_ylabel("Count")
ax4.set_title("L4_DST_PORT: Ports >80% Specific\nto Malicious/Benign Traffic", fontsize=12, fontweight='bold')
ax4.set_xticks(x)
ax4.set_xticklabels([d.replace('NF-', '').replace('-v3', '') for d in datasets_names], rotation=15)
ax4.legend()

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'Cross_Dataset_Comparison.png'), dpi=150, bbox_inches='tight')
plt.close()
print(f"    Saved: Cross_Dataset_Comparison.png", flush=True)

print_header("ANALYSIS COMPLETE")
print(f"\nAll results saved to: {OUTPUT_DIR}/", flush=True)
print("\nGenerated files:", flush=True)
print("  - Port_Correlation_Summary.md (main report)", flush=True)
print("  - Cross_Dataset_Comparison.png", flush=True)
for dataset_name, _ in DATASETS:
    print(f"  - {dataset_name}_L4_SRC_PORT_binary_analysis.png (Binary)", flush=True)
    print(f"  - {dataset_name}_L4_DST_PORT_binary_analysis.png (Binary)", flush=True)
    print(f"  - {dataset_name}_L4_SRC_PORT_analysis.png (Multi-class)", flush=True)
    print(f"  - {dataset_name}_L4_DST_PORT_analysis.png (Multi-class)", flush=True)
    print(f"  - {dataset_name}_attack_ports.png", flush=True)
