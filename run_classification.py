import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    matthews_corrcoef
)
from sklearn.utils.class_weight import compute_class_weight
import matplotlib.pyplot as plt
import seaborn as sns
import os
import warnings
import time
import gc

warnings.filterwarnings('ignore')
np.random.seed(42)

charts_dir = r'c:\Users\josia\Documents\Kill Chain Research\Charts'
os.makedirs(charts_dir, exist_ok=True)

# Cap per ATT&CK tactic class for tractability
MAX_PER_CLASS = 50_000

# Columns to drop (leakage risk)
DROP_COLS = ['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'FLOW_START_MILLISECONDS', 'FLOW_END_MILLISECONDS', 'Label', 'Attack']

# === ATT&CK Mappings (inline) ===
mapping_dict = {
    ('NF-BoT-IoT-v3', 'Benign'): '-',
    ('NF-BoT-IoT-v3', 'DoS'): 'Impact',
    ('NF-BoT-IoT-v3', 'DDoS'): 'Impact',
    ('NF-BoT-IoT-v3', 'Reconnaissance'): 'Reconnaissance',
    ('NF-BoT-IoT-v3', 'Theft'): 'Exfiltration',
    ('NF-CICIDS2018-v3', 'Benign'): '-',
    ('NF-CICIDS2018-v3', 'DDOS_attack-HOIC'): 'Impact',
    ('NF-CICIDS2018-v3', 'FTP-BruteForce'): 'Credential_Access',
    ('NF-CICIDS2018-v3', 'DDoS_attacks-LOIC-HTTP'): 'Impact',
    ('NF-CICIDS2018-v3', 'Bot'): 'Command_and_Control',
    ('NF-CICIDS2018-v3', 'SSH-Bruteforce'): 'Credential_Access',
    ('NF-CICIDS2018-v3', 'Infilteration'): 'Lateral_Movement',
    ('NF-CICIDS2018-v3', 'DoS_attacks-SlowHTTPTest'): 'Impact',
    ('NF-CICIDS2018-v3', 'DoS_attacks-Hulk'): 'Impact',
    ('NF-CICIDS2018-v3', 'DoS_attacks-GoldenEye'): 'Impact',
    ('NF-CICIDS2018-v3', 'DoS_attacks-Slowloris'): 'Impact',
    ('NF-CICIDS2018-v3', 'DDOS_attack-LOIC-UDP'): 'Impact',
    ('NF-CICIDS2018-v3', 'Brute_Force_-Web'): 'Credential_Access',
    ('NF-CICIDS2018-v3', 'Brute_Force_-XSS'): 'Initial_Access',
    ('NF-CICIDS2018-v3', 'SQL_Injection'): 'Initial_Access',
    ('NF-ToN-IoT-v3', 'Benign'): '-',
    ('NF-ToN-IoT-v3', 'ddos'): 'Impact',
    ('NF-ToN-IoT-v3', 'xss'): 'Initial_Access',
    ('NF-ToN-IoT-v3', 'password'): 'Credential_Access',
    ('NF-ToN-IoT-v3', 'scanning'): 'Discovery',
    ('NF-ToN-IoT-v3', 'injection'): 'Execution',
    ('NF-ToN-IoT-v3', 'dos'): 'Impact',
    ('NF-ToN-IoT-v3', 'Backdoor'): 'Persistence',
    ('NF-ToN-IoT-v3', 'mitm'): 'Credential_Access',
    ('NF-ToN-IoT-v3', 'ransomware'): 'Impact',
    ('NF-UNSW-NB15-v3', 'Benign'): '-',
    ('NF-UNSW-NB15-v3', 'Analysis'): 'Reconnaissance',
    ('NF-UNSW-NB15-v3', 'Backdoor'): 'Defense_Evasion',
    ('NF-UNSW-NB15-v3', 'DoS'): 'Impact',
    ('NF-UNSW-NB15-v3', 'Exploits'): 'Initial_Access',
    ('NF-UNSW-NB15-v3', 'Fuzzers'): 'Impact',
    ('NF-UNSW-NB15-v3', 'Generic'): 'Credential_Access',
    ('NF-UNSW-NB15-v3', 'Reconnaissance'): 'Reconnaissance',
    ('NF-UNSW-NB15-v3', 'Shellcode'): 'Defense_Evasion',
    ('NF-UNSW-NB15-v3', 'Worms'): 'Impact',
}

datasets_info = [
    ('NF-BoT-IoT-v3', r'c:\Users\josia\Documents\Kill Chain Research\v3-Datasets\NF-BoT-IoT-v3\data\NF-BoT-IoT-v3.csv'),
    ('NF-CICIDS2018-v3', r'c:\Users\josia\Documents\Kill Chain Research\v3-Datasets\NF-CICIDS2018-v3\data\NF-CICIDS2018-v3.csv'),
    ('NF-ToN-IoT-v3', r'c:\Users\josia\Documents\Kill Chain Research\v3-Datasets\NF-ToN-IoT-v3\data\NF-ToN-IoT-v3.csv'),
    ('NF-UNSW-NB15-v3', r'c:\Users\josia\Documents\Kill Chain Research\v3-Datasets\NF-UNSW-NB15-v3\data\NF-UNSW-NB15-v3.csv'),
]

# === Step 1: Load datasets with per-tactic sampling ===
print("=" * 70, flush=True)
print("STEP 1: Loading datasets with stratified sampling", flush=True)
print(f"  MAX_PER_CLASS = {MAX_PER_CLASS:,} per tactic", flush=True)
print("=" * 70, flush=True)

frames = []
for ds_name, path in datasets_info:
    print(f"\n  Loading {ds_name}...", flush=True)
    df = pd.read_csv(path)
    print(f"    Raw size: {len(df):,}", flush=True)

    # Map to ATT&CK tactic
    df['MITRE_Tactic'] = df['Attack'].map(lambda x: mapping_dict.get((ds_name, x), 'Unknown'))

    # Drop leakage columns
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

    # Sample per tactic: keep all if < MAX_PER_CLASS, else subsample
    sampled = []
    for tactic in df['MITRE_Tactic'].unique():
        tactic_df = df[df['MITRE_Tactic'] == tactic]
        if len(tactic_df) > MAX_PER_CLASS:
            tactic_df = tactic_df.sample(n=MAX_PER_CLASS, random_state=42)
        sampled.append(tactic_df)

    df_sampled = pd.concat(sampled, ignore_index=True)
    print(f"    Sampled size: {len(df_sampled):,}", flush=True)
    frames.append(df_sampled)
    del df, sampled, df_sampled
    gc.collect()

combined = pd.concat(frames, ignore_index=True)
del frames
gc.collect()

print(f"\n  Combined sampled dataset: {len(combined):,} samples", flush=True)
print(f"  Tactic distribution:", flush=True)
for tactic, count in combined['MITRE_Tactic'].value_counts().items():
    print(f"    {tactic:25s}: {count:>8,}", flush=True)

# === Step 2: Preprocessing ===
print("\n" + "=" * 70, flush=True)
print("STEP 2: Preprocessing", flush=True)
print("=" * 70, flush=True)

y_tactic = combined['MITRE_Tactic'].copy()
X = combined.drop(columns=['MITRE_Tactic'])
del combined
gc.collect()

X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
y_binary = (y_tactic != '-').astype(int)

print(f"  Features: {X.shape[1]}", flush=True)
print(f"  Binary: Benign={sum(y_binary==0):,}, Malicious={sum(y_binary==1):,}", flush=True)

# === Step 3: Train/Test Split ===
print("\n" + "=" * 70, flush=True)
print("STEP 3: Train/Test Split (80/20 stratified)", flush=True)
print("=" * 70, flush=True)

X_train, X_test, y_bin_train, y_bin_test, y_tac_train, y_tac_test = train_test_split(
    X, y_binary, y_tactic,
    test_size=0.2, random_state=42, stratify=y_tactic
)
del X, y_binary, y_tactic
gc.collect()

print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}", flush=True)

# === Step 4: Parameter Configurations ===
print("\n" + "=" * 70, flush=True)
print("STEP 4: Parameter Configurations", flush=True)
print("=" * 70, flush=True)

param_configs = {
    'Config_A_Baseline': {
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.1,
        'n_estimators': 200,
        'max_depth': -1,
        'min_child_samples': 20,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'reg_alpha': 0.0,
        'reg_lambda': 0.0,
        'random_state': 42,
        'verbose': -1,
        'n_jobs': -1
    },
    'Config_B_DeepTrees': {
        'boosting_type': 'gbdt',
        'num_leaves': 63,
        'learning_rate': 0.05,
        'n_estimators': 400,
        'max_depth': 12,
        'min_child_samples': 10,
        'subsample': 0.7,
        'colsample_bytree': 0.7,
        'reg_alpha': 0.1,
        'reg_lambda': 0.1,
        'random_state': 42,
        'verbose': -1,
        'n_jobs': -1
    },
    'Config_C_MoreTrees': {
        'boosting_type': 'gbdt',
        'num_leaves': 127,
        'learning_rate': 0.03,
        'n_estimators': 600,
        'max_depth': 15,
        'min_child_samples': 5,
        'subsample': 0.6,
        'colsample_bytree': 0.6,
        'reg_alpha': 1.0,
        'reg_lambda': 1.0,
        'random_state': 42,
        'verbose': -1,
        'n_jobs': -1
    }
}

for name, params in param_configs.items():
    print(f"  {name}: leaves={params['num_leaves']}, lr={params['learning_rate']}, "
          f"trees={params['n_estimators']}, depth={params['max_depth']}", flush=True)

# =====================================================================
# STAGE 1: Binary Classification
# =====================================================================
print("\n" + "=" * 70, flush=True)
print("STAGE 1: Binary Classification (Benign vs Malicious)", flush=True)
print("=" * 70, flush=True)

binary_results = {}

for config_name, params in param_configs.items():
    print(f"\n--- {config_name} ---", flush=True)
    start = time.time()

    bin_params = params.copy()
    bin_params['is_unbalance'] = True

    model_bin = lgb.LGBMClassifier(**bin_params)
    model_bin.fit(X_train, y_bin_train)

    y_pred_bin = model_bin.predict(X_test)
    elapsed = time.time() - start

    f1 = f1_score(y_bin_test, y_pred_bin, average='macro')
    mcc = matthews_corrcoef(y_bin_test, y_pred_bin)

    binary_results[config_name] = {
        'model': model_bin,
        'predictions': y_pred_bin,
        'f1_macro': f1,
        'mcc': mcc,
        'time': elapsed,
        'report': classification_report(y_bin_test, y_pred_bin, target_names=['Benign', 'Malicious'], output_dict=True)
    }

    print(f"  Macro F1: {f1:.4f} | MCC: {mcc:.4f} | Time: {elapsed:.1f}s", flush=True)
    print(classification_report(y_bin_test, y_pred_bin, target_names=['Benign', 'Malicious']), flush=True)

best_bin_config = max(binary_results, key=lambda k: binary_results[k]['f1_macro'])
print(f"\nBest Binary: {best_bin_config} (F1={binary_results[best_bin_config]['f1_macro']:.4f})", flush=True)

# Binary confusion matrices
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
for idx, (config_name, result) in enumerate(binary_results.items()):
    cm = confusion_matrix(y_bin_test, result['predictions'])
    sns.heatmap(cm, annot=True, fmt=',d', cmap='Blues', ax=axes[idx],
                xticklabels=['Benign', 'Malicious'], yticklabels=['Benign', 'Malicious'])
    axes[idx].set_title(f'{config_name}\nF1={result["f1_macro"]:.4f}, MCC={result["mcc"]:.4f}', fontsize=9)
    axes[idx].set_ylabel('True')
    axes[idx].set_xlabel('Predicted')
plt.suptitle('Stage 1: Binary Classification Confusion Matrices', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(charts_dir, 'Stage1_Binary_Confusion_Matrices.png'), dpi=150, bbox_inches='tight')
plt.close()

# =====================================================================
# STAGE 2: Multi-class ATT&CK Tactic Classification
# =====================================================================
print("\n" + "=" * 70, flush=True)
print("STAGE 2: Multi-class ATT&CK Tactic Classification", flush=True)
print("=" * 70, flush=True)

mal_train_mask = y_bin_train == 1
mal_test_mask = y_bin_test == 1

X_train_mal = X_train[mal_train_mask].reset_index(drop=True)
X_test_mal = X_test[mal_test_mask].reset_index(drop=True)
y_train_mal = y_tac_train[mal_train_mask].reset_index(drop=True)
y_test_mal = y_tac_test[mal_test_mask].reset_index(drop=True)

# Remove benign label if any leaked through
mask_train = y_train_mal != '-'
mask_test = y_test_mal != '-'
X_train_mal = X_train_mal[mask_train].reset_index(drop=True)
X_test_mal = X_test_mal[mask_test].reset_index(drop=True)
y_train_mal = y_train_mal[mask_train].reset_index(drop=True)
y_test_mal = y_test_mal[mask_test].reset_index(drop=True)

tactic_classes = sorted(y_train_mal.unique())
tactic_to_idx = {t: i for i, t in enumerate(tactic_classes)}

y_train_enc = y_train_mal.map(tactic_to_idx).astype(int)
y_test_enc = y_test_mal.map(tactic_to_idx).astype(int)

print(f"  Malicious train: {len(X_train_mal):,} | test: {len(X_test_mal):,}", flush=True)
print(f"  Classes ({len(tactic_classes)}): {tactic_classes}", flush=True)

# Class weights
cw = compute_class_weight('balanced', classes=np.arange(len(tactic_classes)), y=y_train_enc)
sample_weights = np.array([cw[y] for y in y_train_enc])

print(f"\n  Class weights:", flush=True)
for i, t in enumerate(tactic_classes):
    n = sum(y_train_enc == i)
    print(f"    {t:25s}: weight={cw[i]:.4f} (n={n:,})", flush=True)

multiclass_results = {}

for config_name, params in param_configs.items():
    print(f"\n--- {config_name} ---", flush=True)
    start = time.time()

    mc_params = params.copy()
    mc_params['objective'] = 'multiclass'
    mc_params['num_class'] = len(tactic_classes)
    mc_params['metric'] = 'multi_logloss'

    model_mc = lgb.LGBMClassifier(**mc_params)
    model_mc.fit(X_train_mal, y_train_enc, sample_weight=sample_weights)

    y_pred_mc = model_mc.predict(X_test_mal)
    elapsed = time.time() - start

    f1_macro = f1_score(y_test_enc, y_pred_mc, average='macro')
    f1_weighted = f1_score(y_test_enc, y_pred_mc, average='weighted')
    mcc = matthews_corrcoef(y_test_enc, y_pred_mc)

    report = classification_report(y_test_enc, y_pred_mc,
                                   target_names=tactic_classes, output_dict=True)

    multiclass_results[config_name] = {
        'model': model_mc,
        'predictions': y_pred_mc,
        'f1_macro': f1_macro,
        'f1_weighted': f1_weighted,
        'mcc': mcc,
        'time': elapsed,
        'report': report
    }

    print(f"  Macro F1: {f1_macro:.4f} | Weighted F1: {f1_weighted:.4f} | MCC: {mcc:.4f} | Time: {elapsed:.1f}s", flush=True)
    print(classification_report(y_test_enc, y_pred_mc, target_names=tactic_classes), flush=True)

best_mc_config = max(multiclass_results, key=lambda k: multiclass_results[k]['f1_macro'])
print(f"\nBest Multi-class: {best_mc_config} (Macro F1={multiclass_results[best_mc_config]['f1_macro']:.4f})", flush=True)

# === Confusion Matrices ===
print("\nGenerating confusion matrix plots...", flush=True)

# Normalized confusion matrices for all configs
fig, axes = plt.subplots(1, 3, figsize=(24, 7))
for idx, (config_name, result) in enumerate(multiclass_results.items()):
    cm = confusion_matrix(y_test_enc, result['predictions'])
    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    sns.heatmap(cm_norm, annot=True, fmt='.2f', cmap='YlOrRd', ax=axes[idx],
                xticklabels=[t.replace('_', '\n') for t in tactic_classes],
                yticklabels=[t.replace('_', '\n') for t in tactic_classes],
                vmin=0, vmax=1)
    axes[idx].set_title(f'{config_name}\nMacro F1={result["f1_macro"]:.4f}', fontsize=9)
    axes[idx].set_ylabel('True')
    axes[idx].set_xlabel('Predicted')
    axes[idx].tick_params(axis='both', labelsize=6)
plt.suptitle('Stage 2: Normalized Confusion Matrices', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(charts_dir, 'Stage2_Multiclass_Confusion_Matrices.png'), dpi=150, bbox_inches='tight')
plt.close()

# Best model raw counts
fig, ax = plt.subplots(figsize=(12, 9))
cm_best = confusion_matrix(y_test_enc, multiclass_results[best_mc_config]['predictions'])
sns.heatmap(cm_best, annot=True, fmt=',d', cmap='YlOrRd', ax=ax,
            xticklabels=tactic_classes, yticklabels=tactic_classes)
ax.set_title(f'Best Model ({best_mc_config}) - Raw Counts', fontsize=13, fontweight='bold')
ax.set_ylabel('True Label')
ax.set_xlabel('Predicted Label')
ax.tick_params(axis='x', rotation=35, labelsize=8)
ax.tick_params(axis='y', rotation=0, labelsize=8)
plt.tight_layout()
plt.savefig(os.path.join(charts_dir, 'Stage2_Best_Confusion_Matrix.png'), dpi=150, bbox_inches='tight')
plt.close()

# === Per-class F1 Comparison ===
fig, ax = plt.subplots(figsize=(14, 7))
x = np.arange(len(tactic_classes))
width = 0.25
for i, (config_name, result) in enumerate(multiclass_results.items()):
    f1_scores = [result['report'][t]['f1-score'] for t in tactic_classes]
    ax.bar(x + i * width - width, f1_scores, width, label=config_name)
ax.set_xticks(x)
ax.set_xticklabels([t.replace('_', ' ') for t in tactic_classes], rotation=35, ha='right', fontsize=9)
ax.set_ylabel('F1-Score')
ax.set_ylim(0, 1.15)
ax.set_title('Per-class F1-Score Across Configurations', fontsize=13, fontweight='bold')
ax.legend(fontsize=8)
ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5)
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(charts_dir, 'Per_Class_F1_Comparison.png'), dpi=150, bbox_inches='tight')
plt.close()

# === Feature Importance ===
print("\nGenerating feature importance...", flush=True)
best_model = multiclass_results[best_mc_config]['model']
importance = best_model.feature_importances_
feat_imp = pd.DataFrame({'feature': X_train_mal.columns.tolist(), 'importance': importance})
feat_imp = feat_imp.sort_values('importance', ascending=False).head(20)

fig, ax = plt.subplots(figsize=(10, 8))
ax.barh(range(len(feat_imp)), feat_imp['importance'].values, color='steelblue')
ax.set_yticks(range(len(feat_imp)))
ax.set_yticklabels(feat_imp['feature'].values, fontsize=9)
ax.invert_yaxis()
ax.set_xlabel('Feature Importance (split count)')
ax.set_title(f'Top 20 Features ({best_mc_config})', fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(charts_dir, 'Feature_Importance_Top20.png'), dpi=150, bbox_inches='tight')
plt.close()

# === Save Summary Report ===
print("\n" + "=" * 70, flush=True)
print("SAVING RESULTS", flush=True)
print("=" * 70, flush=True)

lines = []
lines.append("# Classification Results: MITRE ATT&CK Tactic Prediction\n")
lines.append("## Dataset Summary\n")
lines.append(f"- **Combined samples (before sampling):** ~66.9M")
lines.append(f"- **Sampled for training/testing:** {len(X_train) + len(X_test):,}")
lines.append(f"- **MAX_PER_CLASS:** {MAX_PER_CLASS:,} per tactic per dataset")
lines.append(f"- **Train/Test split:** 80/20 stratified")
lines.append(f"- **Features used:** {X_train.shape[1]} (all NetFlow v3 features minus IPs and timestamps)\n")

lines.append("\n## Stage 1: Binary Classification (Benign vs Malicious)\n")
lines.append("| Config | Macro F1 | MCC | Time (s) |")
lines.append("|--------|----------|-----|----------|")
for cn, r in binary_results.items():
    lines.append(f"| {cn} | {r['f1_macro']:.4f} | {r['mcc']:.4f} | {r['time']:.1f} |")
lines.append(f"\n**Best:** {best_bin_config} (Macro F1={binary_results[best_bin_config]['f1_macro']:.4f})\n")

lines.append("\n## Stage 2: Multi-class ATT&CK Tactic Classification\n")
lines.append("| Config | Macro F1 | Weighted F1 | MCC | Time (s) |")
lines.append("|--------|----------|-------------|-----|----------|")
for cn, r in multiclass_results.items():
    lines.append(f"| {cn} | {r['f1_macro']:.4f} | {r['f1_weighted']:.4f} | {r['mcc']:.4f} | {r['time']:.1f} |")
lines.append(f"\n**Best:** {best_mc_config} (Macro F1={multiclass_results[best_mc_config]['f1_macro']:.4f})\n")

lines.append("\n## Best Model: Per-class Report\n")
lines.append("| ATT&CK Tactic | Precision | Recall | F1-Score | Support |")
lines.append("|---------------|-----------|--------|----------|---------|")
best_report = multiclass_results[best_mc_config]['report']
for t in tactic_classes:
    r = best_report[t]
    lines.append(f"| {t} | {r['precision']:.4f} | {r['recall']:.4f} | {r['f1-score']:.4f} | {int(r['support']):,} |")

lines.append(f"\n\n## Parameter Configurations\n")
for cn, params in param_configs.items():
    lines.append(f"### {cn}\n")
    lines.append("| Parameter | Value |")
    lines.append("|-----------|-------|")
    for k, v in params.items():
        if k not in ['verbose', 'n_jobs', 'random_state']:
            lines.append(f"| {k} | {v} |")
    lines.append("")

lines.append("\n## Top 20 Features\n")
lines.append("| Rank | Feature | Importance |")
lines.append("|------|---------|------------|")
for i, (_, row) in enumerate(feat_imp.iterrows(), 1):
    lines.append(f"| {i} | {row['feature']} | {int(row['importance']):,} |")

with open(os.path.join(charts_dir, 'Classification_Results.md'), 'w') as f:
    f.write('\n'.join(lines))

print("\nAll done! Files saved to Charts/:", flush=True)
print("  - Stage1_Binary_Confusion_Matrices.png", flush=True)
print("  - Stage2_Multiclass_Confusion_Matrices.png", flush=True)
print("  - Stage2_Best_Confusion_Matrix.png", flush=True)
print("  - Per_Class_F1_Comparison.png", flush=True)
print("  - Feature_Importance_Top20.png", flush=True)
print("  - Classification_Results.md", flush=True)
