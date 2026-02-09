import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from huggingface_hub import login

# ── Configuration ────────────────────────────────────────────────────────────
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hackaprompt")
os.makedirs(OUTPUT_DIR, exist_ok=True)

DPI = 150
sns.set_theme(style="whitegrid", palette="deep")


def print_header(text):
    print("\n" + "=" * 70, flush=True)
    print(text, flush=True)
    print("=" * 70, flush=True)


# ── Load Data ────────────────────────────────────────────────────────────────
print_header("LOADING DATA")
login()
df = pd.read_parquet(
    "hf://datasets/hackaprompt/hackaprompt-dataset/hackaprompt.parquet"
)
print(f"Raw dataset shape: {df.shape}")
print(f"Columns: {list(df.columns)}")
print(f"\nData types:\n{df.dtypes}")
print(f"\nMissing values:\n{df.isnull().sum()}")
print(f"\nFirst 5 rows:\n{df.head()}")

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: DATA CLEANING
# ══════════════════════════════════════════════════════════════════════════════
print_header("PHASE 1: DATA CLEANING")

rows_before = len(df)
cleaning_log = []

# 1. Drop exact duplicate rows
dupes = df.duplicated().sum()
df = df.drop_duplicates()
cleaning_log.append(f"Dropped {dupes} exact duplicate rows")
print(f"  [1] Dropped {dupes} duplicate rows  ->  {len(df)} remaining")

# 2. Drop rows missing critical fields
critical_cols = ["user_input", "prompt", "completion", "model", "level"]
missing_critical_before = len(df)
df = df.dropna(subset=critical_cols)
dropped_critical = missing_critical_before - len(df)
cleaning_log.append(
    f"Dropped {dropped_critical} rows missing critical fields ({critical_cols})"
)
print(f"  [2] Dropped {dropped_critical} rows with missing critical fields  ->  {len(df)} remaining")

# 3. Fill optional fields
if "score" in df.columns:
    df["score"] = df["score"].fillna(0)
    cleaning_log.append("Filled missing 'score' values with 0")

# 4. Enforce dtypes
df["level"] = df["level"].astype(int)
df["correct"] = df["correct"].astype(bool)
if "error" in df.columns:
    df["error"] = df["error"].astype(bool)
df["token_count"] = pd.to_numeric(df["token_count"], errors="coerce").fillna(0).astype(int)
if "timestamp" in df.columns:
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
cleaning_log.append("Enforced correct dtypes for level, correct, error, token_count, timestamp")

# 5. Remove error rows
if "error" in df.columns:
    error_count = df["error"].sum()
    df = df[~df["error"]]
    cleaning_log.append(f"Removed {error_count} rows where error == True")
    print(f"  [5] Removed {error_count} error rows  ->  {len(df)} remaining")

# 6. Strip whitespace from string columns
str_cols = df.select_dtypes(include="object").columns
for col in str_cols:
    df[col] = df[col].str.strip()
cleaning_log.append(f"Stripped whitespace from {len(str_cols)} string columns")

rows_after = len(df)
print(f"\nCleaning complete: {rows_before} -> {rows_after} rows ({rows_before - rows_after} removed)")

# 7. Save cleaned dataset
cleaned_path = os.path.join(OUTPUT_DIR, "cleaned_hackaprompt.csv")
df.to_csv(cleaned_path, index=False)
print(f"Saved cleaned dataset to {cleaned_path}")

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2: EXPLORATORY ANALYSIS & VISUALIZATIONS
# ══════════════════════════════════════════════════════════════════════════════
print_header("PHASE 2: EXPLORATORY ANALYSIS")

# Collect findings for the summary report
findings = {}

# ── 2a. Overview Statistics ──────────────────────────────────────────────────
print_header("2a. Overview Statistics")
print(f"Dataset shape: {df.shape}")
print(f"\nDescriptive statistics:\n{df.describe()}")
print(f"\nUnique models: {df['model'].unique()}")
print(f"Unique levels: {sorted(df['level'].unique())}")
if "dataset" in df.columns:
    print(f"Dataset sources: {df['dataset'].unique()}")

findings["shape"] = df.shape
findings["models"] = list(df["model"].unique())
findings["levels"] = sorted(int(x) for x in df["level"].unique())

# ── 2b. Submission Distribution ──────────────────────────────────────────────
print_header("2b. Submission Distribution")

# Submissions per level
level_counts = df["level"].value_counts().sort_index()
findings["level_counts"] = level_counts.to_dict()

fig, ax = plt.subplots(figsize=(10, 6))
level_counts.plot(kind="bar", ax=ax, color=sns.color_palette("deep"))
ax.set_title("Number of Submissions per Challenge Level", fontsize=14, fontweight="bold")
ax.set_xlabel("Challenge Level")
ax.set_ylabel("Number of Submissions")
ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
for i, v in enumerate(level_counts.values):
    ax.text(i, v + max(level_counts) * 0.01, f"{v:,}", ha="center", va="bottom", fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "submissions_per_level.png"), dpi=DPI, bbox_inches="tight")
plt.close()
print("  Saved submissions_per_level.png")

# Submissions per model
model_counts = df["model"].value_counts()
findings["model_counts"] = model_counts.to_dict()

fig, ax = plt.subplots(figsize=(10, 6))
model_counts.plot(kind="bar", ax=ax, color=sns.color_palette("deep"))
ax.set_title("Number of Submissions per Model", fontsize=14, fontweight="bold")
ax.set_xlabel("Model")
ax.set_ylabel("Number of Submissions")
ax.set_xticklabels(ax.get_xticklabels(), rotation=15, ha="right")
for i, v in enumerate(model_counts.values):
    ax.text(i, v + max(model_counts) * 0.01, f"{v:,}", ha="center", va="bottom", fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "submissions_per_model.png"), dpi=DPI, bbox_inches="tight")
plt.close()
print("  Saved submissions_per_model.png")

# Dataset source split
if "dataset" in df.columns:
    source_counts = df["dataset"].value_counts()
    findings["source_counts"] = source_counts.to_dict()

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(
        source_counts.values,
        labels=source_counts.index,
        autopct="%1.1f%%",
        startangle=140,
        colors=sns.color_palette("deep", len(source_counts)),
    )
    ax.set_title("Playground vs. Submission Data", fontsize=14, fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "dataset_source_split.png"), dpi=DPI, bbox_inches="tight")
    plt.close()
    print("  Saved dataset_source_split.png")

# ── 2c. Success Rate Analysis ────────────────────────────────────────────────
print_header("2c. Success Rate Analysis")

# Success rate per level
success_by_level = df.groupby("level")["correct"].mean() * 100
findings["success_by_level"] = success_by_level.to_dict()

fig, ax = plt.subplots(figsize=(10, 6))
success_by_level.plot(kind="bar", ax=ax, color=sns.color_palette("YlOrRd_r", len(success_by_level)))
ax.set_title("Success Rate per Challenge Level", fontsize=14, fontweight="bold")
ax.set_xlabel("Challenge Level")
ax.set_ylabel("Success Rate (%)")
ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
ax.set_ylim(0, 100)
for i, v in enumerate(success_by_level.values):
    ax.text(i, v + 1, f"{v:.1f}%", ha="center", va="bottom", fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "success_rate_per_level.png"), dpi=DPI, bbox_inches="tight")
plt.close()
print("  Saved success_rate_per_level.png")

# Success rate by level and model (grouped bar chart)
success_pivot = df.groupby(["level", "model"])["correct"].mean().unstack() * 100
findings["success_pivot"] = success_pivot.to_dict()

fig, ax = plt.subplots(figsize=(14, 7))
success_pivot.plot(kind="bar", ax=ax)
ax.set_title("Success Rate by Level and Model", fontsize=14, fontweight="bold")
ax.set_xlabel("Challenge Level")
ax.set_ylabel("Success Rate (%)")
ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
ax.set_ylim(0, 100)
ax.legend(title="Model", bbox_to_anchor=(1.05, 1), loc="upper left")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "success_rate_by_level_model.png"), dpi=DPI, bbox_inches="tight")
plt.close()
print("  Saved success_rate_by_level_model.png")

# Heatmap: success rate matrix (level x model)
fig, ax = plt.subplots(figsize=(12, 8))
sns.heatmap(
    success_pivot,
    annot=True,
    fmt=".1f",
    cmap="YlOrRd_r",
    ax=ax,
    vmin=0,
    vmax=100,
    linewidths=0.5,
    cbar_kws={"label": "Success Rate (%)"},
)
ax.set_title("Success Rate Heatmap (Level x Model)", fontsize=14, fontweight="bold")
ax.set_xlabel("Model")
ax.set_ylabel("Challenge Level")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "success_rate_heatmap.png"), dpi=DPI, bbox_inches="tight")
plt.close()
print("  Saved success_rate_heatmap.png")

# ── 2d. Token Count Analysis ─────────────────────────────────────────────────
print_header("2d. Token Count Analysis")

# Token count stats
token_stats = df.groupby("correct")["token_count"].describe()
findings["token_stats"] = token_stats.to_dict()
print(f"Token count stats by success:\n{token_stats}")

# Box plot: token count by level
fig, ax = plt.subplots(figsize=(12, 6))
sns.boxplot(data=df, x="level", y="token_count", hue="level", ax=ax, palette="deep", showfliers=False, legend=False)
ax.set_title("Token Count Distribution by Challenge Level", fontsize=14, fontweight="bold")
ax.set_xlabel("Challenge Level")
ax.set_ylabel("Token Count")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "token_count_by_level.png"), dpi=DPI, bbox_inches="tight")
plt.close()
print("  Saved token_count_by_level.png")

# Violin plot: token count of successful vs failed attempts
fig, ax = plt.subplots(figsize=(10, 6))
df["result"] = df["correct"].map({False: "Failed", True: "Successful"})
sns.violinplot(
    data=df,
    x="result",
    y="token_count",
    hue="result",
    ax=ax,
    palette={"Failed": "#e74c3c", "Successful": "#2ecc71"},
    cut=0,
    legend=False,
    order=["Failed", "Successful"],
)
ax.set_title("Token Count: Successful vs. Failed Attempts", fontsize=14, fontweight="bold")
ax.set_xlabel("")
ax.set_ylabel("Token Count")
df.drop(columns=["result"], inplace=True)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "token_count_success_vs_fail.png"), dpi=DPI, bbox_inches="tight")
plt.close()
print("  Saved token_count_success_vs_fail.png")

# Scatter plot: token count vs level, colored by success (sample to avoid overplotting)
sample_size = min(10000, len(df))
df_sample = df.sample(n=sample_size, random_state=42)

fig, ax = plt.subplots(figsize=(12, 6))
colors = df_sample["correct"].map({True: "#2ecc71", False: "#e74c3c"})
ax.scatter(
    df_sample["level"],
    df_sample["token_count"],
    c=colors,
    alpha=0.3,
    s=10,
)
ax.set_title("Token Count vs. Level (Colored by Success)", fontsize=14, fontweight="bold")
ax.set_xlabel("Challenge Level")
ax.set_ylabel("Token Count")
from matplotlib.lines import Line2D
legend_elements = [
    Line2D([0], [0], marker="o", color="w", markerfacecolor="#2ecc71", markersize=8, label="Successful"),
    Line2D([0], [0], marker="o", color="w", markerfacecolor="#e74c3c", markersize=8, label="Failed"),
]
ax.legend(handles=legend_elements)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "token_vs_level_scatter.png"), dpi=DPI, bbox_inches="tight")
plt.close()
print("  Saved token_vs_level_scatter.png")

# ── 2e. Temporal Analysis ────────────────────────────────────────────────────
print_header("2e. Temporal Analysis")

if "timestamp" in df.columns and df["timestamp"].notna().any():
    df_temporal = df[df["timestamp"].notna()].copy()
    df_temporal["date"] = df_temporal["timestamp"].dt.date

    # Submissions over time
    daily_counts = df_temporal.groupby("date").size()
    findings["temporal_range"] = (str(daily_counts.index.min()), str(daily_counts.index.max()))

    fig, ax = plt.subplots(figsize=(14, 6))
    daily_counts.plot(ax=ax, color="steelblue", linewidth=1.5)
    ax.set_title("Submissions Over Time (Daily Count)", fontsize=14, fontweight="bold")
    ax.set_xlabel("Date")
    ax.set_ylabel("Number of Submissions")
    ax.tick_params(axis="x", rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "submissions_over_time.png"), dpi=DPI, bbox_inches="tight")
    plt.close()
    print("  Saved submissions_over_time.png")

    # Success rate over time (7-day rolling average)
    daily_success = df_temporal.groupby("date")["correct"].mean() * 100
    rolling_success = daily_success.rolling(window=7, min_periods=1).mean()

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.plot(daily_success.index, daily_success.values, alpha=0.3, color="steelblue", label="Daily")
    ax.plot(rolling_success.index, rolling_success.values, color="darkblue", linewidth=2, label="7-Day Rolling Avg")
    ax.set_title("Success Rate Over Time", fontsize=14, fontweight="bold")
    ax.set_xlabel("Date")
    ax.set_ylabel("Success Rate (%)")
    ax.set_ylim(0, 100)
    ax.legend()
    ax.tick_params(axis="x", rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "success_rate_over_time.png"), dpi=DPI, bbox_inches="tight")
    plt.close()
    print("  Saved success_rate_over_time.png")
else:
    print("  No timestamp data available — skipping temporal analysis.")

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2f: SUMMARY REPORT
# ══════════════════════════════════════════════════════════════════════════════
print_header("2f. Generating Summary Report")

report_lines = []
report_lines.append("# HackAPrompt Dataset — Analysis Summary\n")

# Dataset overview
report_lines.append("## 1. Dataset Overview\n")
report_lines.append(f"- **Raw rows**: {rows_before:,}")
report_lines.append(f"- **Cleaned rows**: {rows_after:,}")
report_lines.append(f"- **Rows removed**: {rows_before - rows_after:,}")
report_lines.append(f"- **Columns**: {len(df.columns)}")
report_lines.append(f"- **Models**: {', '.join(findings['models'])}")
report_lines.append(f"- **Challenge levels**: {findings['levels']}\n")

# Cleaning steps
report_lines.append("### Cleaning Steps\n")
for step in cleaning_log:
    report_lines.append(f"- {step}")
report_lines.append("")

# Submission distribution
report_lines.append("## 2. Submission Distribution\n")
report_lines.append("### Submissions per Level\n")
report_lines.append("| Level | Count |")
report_lines.append("|-------|-------|")
for lvl, cnt in sorted(findings["level_counts"].items()):
    report_lines.append(f"| {lvl} | {cnt:,} |")
report_lines.append("")

report_lines.append("### Submissions per Model\n")
report_lines.append("| Model | Count |")
report_lines.append("|-------|-------|")
for model, cnt in findings["model_counts"].items():
    report_lines.append(f"| {model} | {cnt:,} |")
report_lines.append("")

if "source_counts" in findings:
    report_lines.append("### Dataset Source Split\n")
    report_lines.append("| Source | Count |")
    report_lines.append("|--------|-------|")
    for src, cnt in findings["source_counts"].items():
        report_lines.append(f"| {src} | {cnt:,} |")
    report_lines.append("")

# Success rates
report_lines.append("## 3. Success Rate Analysis\n")
report_lines.append("### Success Rate per Level\n")
report_lines.append("| Level | Success Rate (%) |")
report_lines.append("|-------|-----------------|")
for lvl, rate in sorted(findings["success_by_level"].items()):
    report_lines.append(f"| {lvl} | {rate:.2f}% |")
report_lines.append("")

report_lines.append("### Success Rate by Level x Model\n")
report_lines.append("See `success_rate_heatmap.png` for the full matrix.\n")

# Token count
report_lines.append("## 4. Token Count Analysis\n")
report_lines.append("### Token Count by Success/Failure\n")
avg_success = df[df["correct"]]["token_count"].mean()
avg_fail = df[~df["correct"]]["token_count"].mean()
med_success = df[df["correct"]]["token_count"].median()
med_fail = df[~df["correct"]]["token_count"].median()
report_lines.append(f"- **Successful attempts** — Mean: {avg_success:.1f}, Median: {med_success:.1f}")
report_lines.append(f"- **Failed attempts** — Mean: {avg_fail:.1f}, Median: {med_fail:.1f}\n")

# Temporal
if "temporal_range" in findings:
    report_lines.append("## 5. Temporal Analysis\n")
    report_lines.append(f"- **Date range**: {findings['temporal_range'][0]} to {findings['temporal_range'][1]}")
    report_lines.append("- See `submissions_over_time.png` and `success_rate_over_time.png`.\n")

# Output files
report_lines.append("## 6. Output Files\n")
report_lines.append("| File | Description |")
report_lines.append("|------|-------------|")
report_lines.append("| `cleaned_hackaprompt.csv` | Cleaned dataset |")
report_lines.append("| `submissions_per_level.png` | Bar chart of submissions per level |")
report_lines.append("| `submissions_per_model.png` | Bar chart of submissions per model |")
report_lines.append("| `dataset_source_split.png` | Pie chart of data sources |")
report_lines.append("| `success_rate_per_level.png` | Success rate by level |")
report_lines.append("| `success_rate_by_level_model.png` | Grouped bar chart by level & model |")
report_lines.append("| `success_rate_heatmap.png` | Heatmap of success rates |")
report_lines.append("| `token_count_by_level.png` | Box plot of token counts by level |")
report_lines.append("| `token_count_success_vs_fail.png` | Violin plot: success vs failure |")
report_lines.append("| `token_vs_level_scatter.png` | Scatter plot: tokens vs level |")
report_lines.append("| `submissions_over_time.png` | Daily submission counts |")
report_lines.append("| `success_rate_over_time.png` | Success rate trend over time |")

report_path = os.path.join(OUTPUT_DIR, "Analysis_Summary.md")
with open(report_path, "w", encoding="utf-8") as f:
    f.write("\n".join(report_lines) + "\n")
print(f"  Saved Analysis_Summary.md")

print_header("ALL DONE")
print(f"All outputs saved to: {OUTPUT_DIR}")
