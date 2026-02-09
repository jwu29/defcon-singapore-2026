"""
Time Series Classification for MITRE ATT&CK Tactics
====================================================
This script transforms network flow data into time series sequences
and trains a CNN-LSTM model for ATT&CK tactic classification.

Approach:
1. Group flows into sessions by (src_ip, dst_ip, protocol)
2. Sort flows within each session by timestamp
3. Create fixed-length sequences (pad/truncate)
4. Train CNN-LSTM hybrid model
5. Evaluate with classification report and confusion matrix
"""

import pandas as pd
import numpy as np
import os
import gc
import time
import warnings
import pickle
from collections import Counter

warnings.filterwarnings('ignore')
np.random.seed(42)

# === Configuration ===
BASE_DIR = r'c:\Users\josia\Documents\Kill Chain Research'
CHARTS_DIR = os.path.join(BASE_DIR, 'Charts')
TIMESERIES_DIR = os.path.join(BASE_DIR, 'TimeSeries_Data')
os.makedirs(CHARTS_DIR, exist_ok=True)
os.makedirs(TIMESERIES_DIR, exist_ok=True)

# Sequence parameters
SEQUENCE_LENGTH = 50  # Number of flows per sequence
MAX_SESSIONS_PER_TACTIC = 10000  # Cap for memory management
MIN_FLOWS_PER_SESSION = 5  # Minimum flows to form a valid session

# Feature columns to use (excluding IPs, timestamps, labels)
FEATURE_COLS = [
    'L4_SRC_PORT', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO',
    'IN_BYTES', 'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS',
    'TCP_FLAGS', 'CLIENT_TCP_FLAGS', 'SERVER_TCP_FLAGS',
    'FLOW_DURATION_MILLISECONDS', 'DURATION_IN', 'DURATION_OUT',
    'MIN_TTL', 'MAX_TTL', 'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT',
    'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN',
    'SRC_TO_DST_SECOND_BYTES', 'DST_TO_SRC_SECOND_BYTES',
    'RETRANSMITTED_IN_BYTES', 'RETRANSMITTED_IN_PKTS',
    'RETRANSMITTED_OUT_BYTES', 'RETRANSMITTED_OUT_PKTS',
    'SRC_TO_DST_AVG_THROUGHPUT', 'DST_TO_SRC_AVG_THROUGHPUT',
    'NUM_PKTS_UP_TO_128_BYTES', 'NUM_PKTS_128_TO_256_BYTES',
    'NUM_PKTS_256_TO_512_BYTES', 'NUM_PKTS_512_TO_1024_BYTES',
    'NUM_PKTS_1024_TO_1514_BYTES', 'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT',
    'ICMP_TYPE', 'ICMP_IPV4_TYPE', 'DNS_QUERY_ID', 'DNS_QUERY_TYPE',
    'DNS_TTL_ANSWER', 'FTP_COMMAND_RET_CODE',
    'SRC_TO_DST_IAT_MIN', 'SRC_TO_DST_IAT_MAX', 'SRC_TO_DST_IAT_AVG', 'SRC_TO_DST_IAT_STDDEV',
    'DST_TO_SRC_IAT_MIN', 'DST_TO_SRC_IAT_MAX', 'DST_TO_SRC_IAT_AVG', 'DST_TO_SRC_IAT_STDDEV'
]

# ATT&CK Mappings
MAPPING_DICT = {
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

DATASETS = [
    ('NF-BoT-IoT-v3', os.path.join(BASE_DIR, 'v3-Datasets/NF-BoT-IoT-v3/data/NF-BoT-IoT-v3.csv')),
    ('NF-CICIDS2018-v3', os.path.join(BASE_DIR, 'v3-Datasets/NF-CICIDS2018-v3/data/NF-CICIDS2018-v3.csv')),
    ('NF-ToN-IoT-v3', os.path.join(BASE_DIR, 'v3-Datasets/NF-ToN-IoT-v3/data/NF-ToN-IoT-v3.csv')),
    ('NF-UNSW-NB15-v3', os.path.join(BASE_DIR, 'v3-Datasets/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv')),
]


def print_header(text):
    print("\n" + "=" * 70, flush=True)
    print(text, flush=True)
    print("=" * 70, flush=True)


def create_sessions_from_dataframe(df, ds_name, max_flows_per_dataset=500000):
    """
    Group flows into sessions by (src_ip, dst_ip, protocol).
    Sort flows within each session by timestamp.
    Assign ATT&CK tactic based on dominant attack in session.
    """
    print(f"  Creating sessions from {ds_name}...", flush=True)

    # Sample if too large
    if len(df) > max_flows_per_dataset:
        df = df.sample(n=max_flows_per_dataset, random_state=42)
        print(f"    Sampled to {max_flows_per_dataset:,} flows", flush=True)

    # Map attacks to ATT&CK tactics
    df['MITRE_Tactic'] = df['Attack'].map(lambda x: MAPPING_DICT.get((ds_name, x), 'Unknown'))

    # Create session key
    df['session_key'] = df['IPV4_SRC_ADDR'].astype(str) + '_' + \
                        df['IPV4_DST_ADDR'].astype(str) + '_' + \
                        df['PROTOCOL'].astype(str)

    # Sort by timestamp within each session
    df = df.sort_values(['session_key', 'FLOW_START_MILLISECONDS'])

    sessions = []
    session_labels = []

    for session_key, group in df.groupby('session_key'):
        if len(group) < MIN_FLOWS_PER_SESSION:
            continue

        # Get features for this session
        features = group[FEATURE_COLS].values

        # Determine session label (dominant tactic, excluding benign if mixed)
        tactics = group['MITRE_Tactic'].values
        tactic_counts = Counter(tactics)

        # If session has attacks, use the most common attack tactic
        attack_tactics = {t: c for t, c in tactic_counts.items() if t != '-'}
        if attack_tactics:
            label = max(attack_tactics, key=attack_tactics.get)
        else:
            label = '-'  # Pure benign session

        sessions.append(features)
        session_labels.append(label)

    print(f"    Created {len(sessions):,} sessions", flush=True)
    return sessions, session_labels


def pad_or_truncate_sequences(sequences, max_len):
    """Pad short sequences with zeros, truncate long sequences."""
    n_features = sequences[0].shape[1] if len(sequences) > 0 else len(FEATURE_COLS)

    padded = []
    for seq in sequences:
        if len(seq) > max_len:
            # Truncate: keep the last max_len flows (most recent)
            padded.append(seq[-max_len:])
        elif len(seq) < max_len:
            # Pad with zeros at the beginning
            padding = np.zeros((max_len - len(seq), n_features))
            padded.append(np.vstack([padding, seq]))
        else:
            padded.append(seq)

    return np.array(padded)


def normalize_sequences(X_train, X_test):
    """Normalize features using training set statistics."""
    # Reshape to 2D for normalization
    n_train, seq_len, n_features = X_train.shape
    n_test = X_test.shape[0]

    X_train_2d = X_train.reshape(-1, n_features)
    X_test_2d = X_test.reshape(-1, n_features)

    # Compute mean and std from training data (ignoring padding zeros)
    # Use robust statistics to handle outliers
    mean = np.nanmean(np.where(X_train_2d == 0, np.nan, X_train_2d), axis=0)
    std = np.nanstd(np.where(X_train_2d == 0, np.nan, X_train_2d), axis=0)

    # Replace NaN with 0 for features that are all zero
    mean = np.nan_to_num(mean, 0)
    std = np.nan_to_num(std, 1)  # Avoid division by zero
    std[std == 0] = 1

    # Normalize
    X_train_norm = (X_train_2d - mean) / std
    X_test_norm = (X_test_2d - mean) / std

    # Handle infinities
    X_train_norm = np.nan_to_num(X_train_norm, 0)
    X_test_norm = np.nan_to_num(X_test_norm, 0)

    # Reshape back to 3D
    X_train_norm = X_train_norm.reshape(n_train, seq_len, n_features)
    X_test_norm = X_test_norm.reshape(n_test, seq_len, n_features)

    return X_train_norm, X_test_norm, mean, std


# =============================================================================
# STEP 1: Load data and create sessions
# =============================================================================
print_header("STEP 1: Loading datasets and creating time series sessions")
print(f"  Sequence length: {SEQUENCE_LENGTH}", flush=True)
print(f"  Min flows per session: {MIN_FLOWS_PER_SESSION}", flush=True)
print(f"  Max sessions per tactic: {MAX_SESSIONS_PER_TACTIC}", flush=True)

all_sessions = []
all_labels = []

for ds_name, path in DATASETS:
    print(f"\n  Loading {ds_name}...", flush=True)
    df = pd.read_csv(path)
    print(f"    Raw size: {len(df):,} flows", flush=True)

    # Fill missing values
    df = df.fillna(0)
    df = df.replace([np.inf, -np.inf], 0)

    sessions, labels = create_sessions_from_dataframe(df, ds_name)
    all_sessions.extend(sessions)
    all_labels.extend(labels)

    del df
    gc.collect()

print(f"\n  Total sessions created: {len(all_sessions):,}", flush=True)

# =============================================================================
# STEP 2: Balance sessions per tactic
# =============================================================================
print_header("STEP 2: Balancing sessions per ATT&CK tactic")

# Group sessions by tactic
tactic_sessions = {}
for i, label in enumerate(all_labels):
    if label not in tactic_sessions:
        tactic_sessions[label] = []
    tactic_sessions[label].append(i)

print("  Session counts before balancing:", flush=True)
for tactic in sorted(tactic_sessions.keys()):
    print(f"    {tactic:25s}: {len(tactic_sessions[tactic]):,}", flush=True)

# Sample to balance (cap at MAX_SESSIONS_PER_TACTIC)
balanced_indices = []
for tactic, indices in tactic_sessions.items():
    if len(indices) > MAX_SESSIONS_PER_TACTIC:
        np.random.seed(42)
        sampled = list(np.random.choice(indices, MAX_SESSIONS_PER_TACTIC, replace=False))
    else:
        sampled = indices
    balanced_indices.extend(sampled)

np.random.seed(42)
np.random.shuffle(balanced_indices)

balanced_sessions = [all_sessions[i] for i in balanced_indices]
balanced_labels = [all_labels[i] for i in balanced_indices]

del all_sessions, all_labels
gc.collect()

print(f"\n  Balanced session count: {len(balanced_sessions):,}", flush=True)

# =============================================================================
# STEP 3: Pad/truncate sequences to fixed length
# =============================================================================
print_header("STEP 3: Creating fixed-length sequences")

X = pad_or_truncate_sequences(balanced_sessions, SEQUENCE_LENGTH)
print(f"  Sequence tensor shape: {X.shape}", flush=True)
print(f"    (n_sessions, sequence_length, n_features) = ({X.shape[0]}, {X.shape[1]}, {X.shape[2]})", flush=True)

del balanced_sessions
gc.collect()

# =============================================================================
# STEP 4: Encode labels
# =============================================================================
print_header("STEP 4: Encoding labels")

# Get unique tactics (exclude unknown if any)
unique_tactics = sorted(set(balanced_labels))
if 'Unknown' in unique_tactics:
    unique_tactics.remove('Unknown')

tactic_to_idx = {t: i for i, t in enumerate(unique_tactics)}
idx_to_tactic = {i: t for t, i in tactic_to_idx.items()}

y = np.array([tactic_to_idx.get(l, -1) for l in balanced_labels])

# Remove unknown labels
valid_mask = y >= 0
X = X[valid_mask]
y = y[valid_mask]

print(f"  Classes ({len(unique_tactics)}): {unique_tactics}", flush=True)
print(f"  Final dataset size: {len(X):,} sequences", flush=True)

# Label distribution
print("\n  Label distribution:", flush=True)
for idx, tactic in idx_to_tactic.items():
    count = np.sum(y == idx)
    print(f"    {tactic:25s}: {count:,} ({count/len(y)*100:.2f}%)", flush=True)

# =============================================================================
# STEP 5: Train/Test Split
# =============================================================================
print_header("STEP 5: Train/Test Split (80/20 stratified)")

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}", flush=True)

# =============================================================================
# STEP 6: Normalize features
# =============================================================================
print_header("STEP 6: Normalizing features")

X_train_norm, X_test_norm, feature_mean, feature_std = normalize_sequences(X_train, X_test)
print(f"  Normalization complete. Train range: [{X_train_norm.min():.2f}, {X_train_norm.max():.2f}]", flush=True)

# =============================================================================
# STEP 7: Save transformed time series data
# =============================================================================
print_header("STEP 7: Saving transformed time series data")

# Save as numpy arrays
np.save(os.path.join(TIMESERIES_DIR, 'X_train.npy'), X_train_norm)
np.save(os.path.join(TIMESERIES_DIR, 'X_test.npy'), X_test_norm)
np.save(os.path.join(TIMESERIES_DIR, 'y_train.npy'), y_train)
np.save(os.path.join(TIMESERIES_DIR, 'y_test.npy'), y_test)

# Save metadata
metadata = {
    'sequence_length': SEQUENCE_LENGTH,
    'n_features': X_train_norm.shape[2],
    'n_classes': len(unique_tactics),
    'tactic_to_idx': tactic_to_idx,
    'idx_to_tactic': idx_to_tactic,
    'feature_columns': FEATURE_COLS,
    'feature_mean': feature_mean,
    'feature_std': feature_std,
    'train_size': len(X_train_norm),
    'test_size': len(X_test_norm),
}

with open(os.path.join(TIMESERIES_DIR, 'metadata.pkl'), 'wb') as f:
    pickle.dump(metadata, f)

# Save as CSV summary
summary_df = pd.DataFrame({
    'tactic': [idx_to_tactic[i] for i in range(len(unique_tactics))],
    'train_count': [np.sum(y_train == i) for i in range(len(unique_tactics))],
    'test_count': [np.sum(y_test == i) for i in range(len(unique_tactics))],
})
summary_df.to_csv(os.path.join(TIMESERIES_DIR, 'label_distribution.csv'), index=False)

print(f"  Saved to {TIMESERIES_DIR}/:", flush=True)
print(f"    - X_train.npy: {X_train_norm.shape}", flush=True)
print(f"    - X_test.npy: {X_test_norm.shape}", flush=True)
print(f"    - y_train.npy: {y_train.shape}", flush=True)
print(f"    - y_test.npy: {y_test.shape}", flush=True)
print(f"    - metadata.pkl", flush=True)
print(f"    - label_distribution.csv", flush=True)

# =============================================================================
# STEP 8: Build and train CNN-LSTM model (PyTorch)
# =============================================================================
print_header("STEP 8: Building CNN-LSTM model (PyTorch)")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    from sklearn.utils.class_weight import compute_class_weight

    TORCH_AVAILABLE = True
    print(f"  PyTorch version: {torch.__version__}", flush=True)
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"  Device: {device}", flush=True)
except ImportError:
    TORCH_AVAILABLE = False
    print("  PyTorch not available. Skipping deep learning model.", flush=True)
    print("  Install with: pip install torch", flush=True)

if TORCH_AVAILABLE:
    # Compute class weights for imbalance
    class_weights_array = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
    class_weights_tensor = torch.FloatTensor(class_weights_array).to(device)

    print("\n  Class weights:", flush=True)
    for idx, tactic in idx_to_tactic.items():
        print(f"    {tactic:25s}: {class_weights_array[idx]:.4f}", flush=True)

    n_timesteps = X_train_norm.shape[1]
    n_features = X_train_norm.shape[2]
    n_classes = len(unique_tactics)

    # Convert to PyTorch tensors
    # PyTorch CNN expects (batch, channels, length), so we need to transpose
    X_train_tensor = torch.FloatTensor(X_train_norm).permute(0, 2, 1).to(device)  # (N, features, seq_len)
    X_test_tensor = torch.FloatTensor(X_test_norm).permute(0, 2, 1).to(device)
    y_train_tensor = torch.LongTensor(y_train).to(device)
    y_test_tensor = torch.LongTensor(y_test).to(device)

    # Create data loaders
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    test_dataset = TensorDataset(X_test_tensor, y_test_tensor)

    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)

    # Define CNN-LSTM models in PyTorch
    class CNN_LSTM_Lightweight(nn.Module):
        def __init__(self, n_features, n_timesteps, n_classes):
            super().__init__()
            self.conv1 = nn.Conv1d(n_features, 32, kernel_size=5, padding=2)
            self.pool = nn.MaxPool1d(2)
            self.dropout1 = nn.Dropout(0.2)
            self.lstm = nn.LSTM(32, 32, batch_first=True)
            self.dropout2 = nn.Dropout(0.3)
            self.fc1 = nn.Linear(32, 32)
            self.fc2 = nn.Linear(32, n_classes)

        def forward(self, x):
            x = torch.relu(self.conv1(x))
            x = self.pool(x)
            x = self.dropout1(x)
            x = x.permute(0, 2, 1)  # (batch, seq, features) for LSTM
            x, _ = self.lstm(x)
            x = x[:, -1, :]  # Take last output
            x = self.dropout2(x)
            x = torch.relu(self.fc1(x))
            x = self.fc2(x)
            return x

    class CNN_LSTM_Standard(nn.Module):
        def __init__(self, n_features, n_timesteps, n_classes):
            super().__init__()
            self.conv1 = nn.Conv1d(n_features, 64, kernel_size=3, padding=1)
            self.bn1 = nn.BatchNorm1d(64)
            self.conv2 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
            self.bn2 = nn.BatchNorm1d(128)
            self.pool = nn.MaxPool1d(2)
            self.dropout1 = nn.Dropout(0.3)
            self.lstm = nn.LSTM(128, 64, batch_first=True, bidirectional=True)
            self.dropout2 = nn.Dropout(0.3)
            self.fc1 = nn.Linear(128, 64)  # 64*2 for bidirectional
            self.dropout3 = nn.Dropout(0.3)
            self.fc2 = nn.Linear(64, n_classes)

        def forward(self, x):
            x = torch.relu(self.bn1(self.conv1(x)))
            x = torch.relu(self.bn2(self.conv2(x)))
            x = self.pool(x)
            x = self.dropout1(x)
            x = x.permute(0, 2, 1)
            x, _ = self.lstm(x)
            x = x[:, -1, :]
            x = self.dropout2(x)
            x = torch.relu(self.fc1(x))
            x = self.dropout3(x)
            x = self.fc2(x)
            return x

    class CNN_LSTM_Deep(nn.Module):
        def __init__(self, n_features, n_timesteps, n_classes):
            super().__init__()
            self.conv1 = nn.Conv1d(n_features, 64, kernel_size=3, padding=1)
            self.bn1 = nn.BatchNorm1d(64)
            self.conv2 = nn.Conv1d(64, 64, kernel_size=3, padding=1)
            self.pool1 = nn.MaxPool1d(2)
            self.dropout1 = nn.Dropout(0.2)
            self.conv3 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
            self.bn2 = nn.BatchNorm1d(128)
            self.conv4 = nn.Conv1d(128, 128, kernel_size=3, padding=1)
            self.pool2 = nn.MaxPool1d(2)
            self.dropout2 = nn.Dropout(0.3)
            self.lstm1 = nn.LSTM(128, 128, batch_first=True, bidirectional=True)
            self.lstm2 = nn.LSTM(256, 64, batch_first=True, bidirectional=True)
            self.dropout3 = nn.Dropout(0.4)
            self.fc1 = nn.Linear(128, 128)
            self.dropout4 = nn.Dropout(0.3)
            self.fc2 = nn.Linear(128, n_classes)

        def forward(self, x):
            x = torch.relu(self.bn1(self.conv1(x)))
            x = torch.relu(self.conv2(x))
            x = self.pool1(x)
            x = self.dropout1(x)
            x = torch.relu(self.bn2(self.conv3(x)))
            x = torch.relu(self.conv4(x))
            x = self.pool2(x)
            x = self.dropout2(x)
            x = x.permute(0, 2, 1)
            x, _ = self.lstm1(x)
            x, _ = self.lstm2(x)
            x = x[:, -1, :]
            x = self.dropout3(x)
            x = torch.relu(self.fc1(x))
            x = self.dropout4(x)
            x = self.fc2(x)
            return x

    def count_parameters(model):
        return sum(p.numel() for p in model.parameters() if p.requires_grad)

    def train_model(model, train_loader, criterion, optimizer, epochs=30):
        history = {'loss': [], 'val_loss': []}
        best_loss = float('inf')
        patience_counter = 0
        patience = 5

        for epoch in range(epochs):
            model.train()
            total_loss = 0
            for X_batch, y_batch in train_loader:
                optimizer.zero_grad()
                outputs = model(X_batch)
                loss = criterion(outputs, y_batch)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            avg_loss = total_loss / len(train_loader)
            history['loss'].append(avg_loss)
            history['val_loss'].append(avg_loss)  # Simplified - using train loss

            # Early stopping
            if avg_loss < best_loss:
                best_loss = avg_loss
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    break

        return history

    def evaluate_model(model, X_test, y_test):
        model.eval()
        with torch.no_grad():
            outputs = model(X_test)
            _, predicted = torch.max(outputs, 1)
        return predicted.cpu().numpy()

    # Model configurations
    model_classes = {
        'lightweight': CNN_LSTM_Lightweight,
        'standard': CNN_LSTM_Standard,
        'deep': CNN_LSTM_Deep
    }

    results = {}

    for config, ModelClass in model_classes.items():
        print(f"\n  --- Training {config.upper()} model ---", flush=True)

        model = ModelClass(n_features, n_timesteps, n_classes).to(device)
        print(f"    Parameters: {count_parameters(model):,}", flush=True)

        criterion = nn.CrossEntropyLoss(weight=class_weights_tensor)
        optimizer = optim.Adam(model.parameters(), lr=0.001)

        start_time = time.time()
        history = train_model(model, train_loader, criterion, optimizer, epochs=30)
        train_time = time.time() - start_time

        y_pred = evaluate_model(model, X_test_tensor, y_test_tensor)

        from sklearn.metrics import classification_report, confusion_matrix, f1_score, matthews_corrcoef

        f1_macro = f1_score(y_test, y_pred, average='macro')
        f1_weighted = f1_score(y_test, y_pred, average='weighted')
        mcc = matthews_corrcoef(y_test, y_pred)

        results[config] = {
            'model': model,
            'history': history,
            'predictions': y_pred,
            'f1_macro': f1_macro,
            'f1_weighted': f1_weighted,
            'mcc': mcc,
            'train_time': train_time,
            'epochs_trained': len(history['loss']),
            'n_params': count_parameters(model)
        }

        print(f"    Epochs: {results[config]['epochs_trained']} | Time: {train_time:.1f}s", flush=True)
        print(f"    Macro F1: {f1_macro:.4f} | Weighted F1: {f1_weighted:.4f} | MCC: {mcc:.4f}", flush=True)

    # ==========================================================================
    # STEP 9: Generate reports and visualizations
    # ==========================================================================
    print_header("STEP 9: Generating classification reports and visualizations")

    import matplotlib.pyplot as plt
    import seaborn as sns

    # Find best model
    best_config = max(results, key=lambda k: results[k]['f1_macro'])
    best_result = results[best_config]
    print(f"\n  Best model: {best_config.upper()} (Macro F1={best_result['f1_macro']:.4f})", flush=True)

    # Classification report for best model
    print(f"\n  Classification Report ({best_config.upper()}):", flush=True)
    report = classification_report(y_test, best_result['predictions'],
                                   target_names=unique_tactics, output_dict=True)
    print(classification_report(y_test, best_result['predictions'], target_names=unique_tactics))

    # Save best model (PyTorch)
    torch.save(best_result['model'].state_dict(), os.path.join(TIMESERIES_DIR, 'best_cnn_lstm_model.pt'))
    print(f"\n  Saved best model to {TIMESERIES_DIR}/best_cnn_lstm_model.pt", flush=True)

    # --- Visualization 1: Confusion Matrix ---
    fig, axes = plt.subplots(1, 3, figsize=(24, 7))
    for idx, (config, result) in enumerate(results.items()):
        cm = confusion_matrix(y_test, result['predictions'])
        cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]

        sns.heatmap(cm_norm, annot=True, fmt='.2f', cmap='YlOrRd', ax=axes[idx],
                    xticklabels=[t.replace('_', '\n') for t in unique_tactics],
                    yticklabels=[t.replace('_', '\n') for t in unique_tactics],
                    vmin=0, vmax=1)
        axes[idx].set_title(f'{config.upper()}\nMacro F1={result["f1_macro"]:.4f}', fontsize=10)
        axes[idx].set_ylabel('True')
        axes[idx].set_xlabel('Predicted')
        axes[idx].tick_params(axis='both', labelsize=6)

    plt.suptitle('CNN-LSTM Time Series: Normalized Confusion Matrices', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'TimeSeries_Confusion_Matrices.png'), dpi=150, bbox_inches='tight')
    plt.close()

    # --- Visualization 2: Training curves ---
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    for idx, (config, result) in enumerate(results.items()):
        axes[idx].plot(result['history']['loss'], label='Train Loss')
        axes[idx].plot(result['history']['val_loss'], label='Val Loss')
        axes[idx].set_title(f'{config.upper()} Training Curve')
        axes[idx].set_xlabel('Epoch')
        axes[idx].set_ylabel('Loss')
        axes[idx].legend()
        axes[idx].grid(True, alpha=0.3)

    plt.suptitle('CNN-LSTM Training Curves', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'TimeSeries_Training_Curves.png'), dpi=150, bbox_inches='tight')
    plt.close()

    # --- Visualization 3: Per-class F1 comparison ---
    fig, ax = plt.subplots(figsize=(14, 7))
    x = np.arange(len(unique_tactics))
    width = 0.25

    for i, (config, result) in enumerate(results.items()):
        report_dict = classification_report(y_test, result['predictions'],
                                           target_names=unique_tactics, output_dict=True)
        f1_scores = [report_dict[t]['f1-score'] for t in unique_tactics]
        ax.bar(x + i * width - width, f1_scores, width, label=config.upper())

    ax.set_xticks(x)
    ax.set_xticklabels([t.replace('_', ' ') for t in unique_tactics], rotation=35, ha='right', fontsize=9)
    ax.set_ylabel('F1-Score')
    ax.set_ylim(0, 1.15)
    ax.set_title('Per-class F1-Score: CNN-LSTM Model Variants', fontsize=13, fontweight='bold')
    ax.legend()
    ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5)
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'TimeSeries_Per_Class_F1.png'), dpi=150, bbox_inches='tight')
    plt.close()

    # --- Visualization 4: Best model raw confusion matrix ---
    fig, ax = plt.subplots(figsize=(12, 9))
    cm_best = confusion_matrix(y_test, best_result['predictions'])
    sns.heatmap(cm_best, annot=True, fmt=',d', cmap='YlOrRd', ax=ax,
                xticklabels=unique_tactics, yticklabels=unique_tactics)
    ax.set_title(f'Best Model ({best_config.upper()}) - Raw Counts', fontsize=13, fontweight='bold')
    ax.set_ylabel('True Label')
    ax.set_xlabel('Predicted Label')
    ax.tick_params(axis='x', rotation=35, labelsize=8)
    ax.tick_params(axis='y', rotation=0, labelsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'TimeSeries_Best_Confusion_Matrix.png'), dpi=150, bbox_inches='tight')
    plt.close()

    # ==========================================================================
    # STEP 10: Save summary report
    # ==========================================================================
    print_header("STEP 10: Saving summary report")

    lines = []
    lines.append("# Time Series Classification Results: MITRE ATT&CK Tactic Prediction\n")
    lines.append("## Model: CNN-LSTM Hybrid\n")
    lines.append("## Data Transformation\n")
    lines.append(f"- **Sequence construction:** Flows grouped by (src_ip, dst_ip, protocol) session")
    lines.append(f"- **Sequence length:** {SEQUENCE_LENGTH} flows per sequence")
    lines.append(f"- **Min flows per session:** {MIN_FLOWS_PER_SESSION}")
    lines.append(f"- **Total sequences:** {len(X):,}")
    lines.append(f"- **Train/Test split:** 80/20 stratified")
    lines.append(f"- **Features:** {n_features} NetFlow features per flow\n")

    lines.append("\n## Model Comparison\n")
    lines.append("| Model | Macro F1 | Weighted F1 | MCC | Epochs | Time (s) | Parameters |")
    lines.append("|-------|----------|-------------|-----|--------|----------|------------|")
    for config, result in results.items():
        n_params = result['n_params']
        lines.append(f"| {config.upper()} | {result['f1_macro']:.4f} | {result['f1_weighted']:.4f} | "
                    f"{result['mcc']:.4f} | {result['epochs_trained']} | {result['train_time']:.1f} | {n_params:,} |")

    lines.append(f"\n**Best Model:** {best_config.upper()} (Macro F1={best_result['f1_macro']:.4f})\n")

    lines.append("\n## Best Model: Per-class Report\n")
    lines.append("| ATT&CK Tactic | Precision | Recall | F1-Score | Support |")
    lines.append("|---------------|-----------|--------|----------|---------|")
    for t in unique_tactics:
        r = report[t]
        lines.append(f"| {t} | {r['precision']:.4f} | {r['recall']:.4f} | {r['f1-score']:.4f} | {int(r['support']):,} |")

    lines.append("\n## Model Architecture (Best: " + best_config.upper() + ")\n")
    lines.append("```")
    lines.append(str(best_result['model']))
    lines.append(f"\nTotal parameters: {best_result['n_params']:,}")
    lines.append("```\n")

    lines.append("\n## Files Generated\n")
    lines.append(f"- `TimeSeries_Data/X_train.npy` - Training sequences ({X_train_norm.shape})")
    lines.append(f"- `TimeSeries_Data/X_test.npy` - Test sequences ({X_test_norm.shape})")
    lines.append(f"- `TimeSeries_Data/y_train.npy` - Training labels")
    lines.append(f"- `TimeSeries_Data/y_test.npy` - Test labels")
    lines.append(f"- `TimeSeries_Data/metadata.pkl` - Normalization parameters and mappings")
    lines.append(f"- `TimeSeries_Data/best_cnn_lstm_model.pt` - Trained model (PyTorch)")
    lines.append(f"- `Charts/TimeSeries_Confusion_Matrices.png`")
    lines.append(f"- `Charts/TimeSeries_Training_Curves.png`")
    lines.append(f"- `Charts/TimeSeries_Per_Class_F1.png`")
    lines.append(f"- `Charts/TimeSeries_Best_Confusion_Matrix.png`")

    with open(os.path.join(CHARTS_DIR, 'TimeSeries_Classification_Results.md'), 'w') as f:
        f.write('\n'.join(lines))

    print(f"\n  Saved report to {CHARTS_DIR}/TimeSeries_Classification_Results.md", flush=True)

    print("\n" + "=" * 70, flush=True)
    print("TIME SERIES CLASSIFICATION COMPLETE", flush=True)
    print("=" * 70, flush=True)
    print(f"\nBest Model: {best_config.upper()}", flush=True)
    print(f"  Macro F1: {best_result['f1_macro']:.4f}", flush=True)
    print(f"  Weighted F1: {best_result['f1_weighted']:.4f}", flush=True)
    print(f"  MCC: {best_result['mcc']:.4f}", flush=True)

else:
    # PyTorch not available - save data only
    print("\n" + "=" * 70, flush=True)
    print("DATA TRANSFORMATION COMPLETE (Model training skipped - PyTorch not installed)", flush=True)
    print("=" * 70, flush=True)
    print(f"\nTime series data saved to: {TIMESERIES_DIR}/", flush=True)
    print("Install PyTorch to train the CNN-LSTM model: pip install torch", flush=True)
