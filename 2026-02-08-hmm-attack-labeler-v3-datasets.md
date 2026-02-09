# Unsupervised HMM-Based MITRE ATT&CK Labeling Tool — v3-Datasets Edition

## Overview

Build an unsupervised Hidden Markov Model tool that discovers attack phases from NetFlow v3 sequences without using existing labels, then maps learned states to MITRE ATT&CK tactics. Targets all four v3-Datasets (~66.9M total flows) as both training and validation corpora.

## What Changed from the Zeek/UWF Edition

| Aspect         | Zeek (original)                  | NetFlow v3 (this doc)                                                 |
| -------------- | -------------------------------- | --------------------------------------------------------------------- |
| Data format    | Parquet (DuckDB)                 | CSV (pandas, chunked)                                                 |
| Feature schema | ~12 hand-crafted features        | 46 numeric NetFlow v3 columns available directly                      |
| Session key    | `src_ip` + 30min gap             | `IPV4_SRC_ADDR` + `IPV4_DST_ADDR` + timestamp gap                     |
| Ground truth   | None (fully unsupervised)        | `Label` (binary) + `Attack` (multi-class) for validation              |
| ATT&CK mapping | Post-hoc signature matching only | Validate against existing `mapping_dict` from `run_classification.py` |
| Scale          | ~1.9M flows (1 dataset)          | ~66.9M flows (4 datasets)                                             |
| Datasets       | UWF-ZeekData24                   | NF-BoT-IoT-v3, NF-CICIDS2018-v3, NF-ToN-IoT-v3, NF-UNSW-NB15-v3       |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  HMM Flow Labeler Pipeline (v3)                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  v3 CSVs ──▶ Session Builder ──▶ Feature Selector/Scaler       │
│      │             │                      │                     │
│      │        (by src+dst IP,       (select from 46             │
│      │         timestamp gap)        numeric cols,              │
│      │             │                 StandardScaler)             │
│      │             ▼                      │                     │
│      ▼    ┌───────────────────────────────────────────────┐     │
│           │            Gaussian HMM (hmmlearn)            │     │
│           │  - 10 hidden states (or BIC-selected)         │     │
│           │  - Per-dataset or combined training            │     │
│           │  - Baum-Welch unsupervised training            │     │
│           │  - Viterbi decoding for labeling               │     │
│           └───────────────────────────────────────────────┘     │
│                              │                                  │
│                              ▼                                  │
│           ┌───────────────────────────────────────────────┐     │
│           │           State Interpreter                    │     │
│           │  - Compute state emission signatures           │     │
│           │  - Match to MITRE tactic profiles              │     │
│           │  - Analyze transition matrix for kill chains   │     │
│           └───────────────────────────────────────────────┘     │
│                              │                                  │
│                              ▼                                  │
│           ┌───────────────────────────────────────────────┐     │
│           │        Validation (NEW for v3)                 │     │
│           │  - Compare HMM labels to ground-truth Attack   │     │
│           │  - ARI, NMI, purity per dataset                │     │
│           │  - Confusion: HMM state vs ATT&CK tactic       │     │
│           └───────────────────────────────────────────────┘     │
│                              │                                  │
│  Output: Labeled CSV with HMM_STATE, HMM_TACTIC, CONFIDENCE    │
└─────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

| Decision      | Choice                                            | Rationale                                                                              |
| ------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Model type    | Gaussian HMM                                      | NetFlow v3 features are continuous; handles multimodal distributions                   |
| Library       | hmmlearn                                          | Well-maintained, scikit-learn compatible                                               |
| States        | 10 (with BIC selection)                           | Covers key MITRE tactics + benign + transitional                                       |
| Sequence def  | Per (src_ip, dst_ip) pair, timestamp-gap boundary | NetFlow v3 has explicit start/end timestamps                                           |
| Features      | 18 selected from 46 available                     | Volume, temporal, throughput, packet-size distribution, protocol                       |
| Training mode | Per-dataset first, then combined                  | Datasets have different attack profiles; per-dataset reveals dataset-specific patterns |
| Sampling      | 50K per dataset for training                      | ~66.9M total is too large; matches `run_classification.py` pattern                     |
| Validation    | ARI + NMI against ground truth                    | v3-Datasets have `Label`/`Attack` columns — use them                                   |

## Datasets

```python
datasets_info = [
    ('NF-BoT-IoT-v3',     r'v3-Datasets\NF-BoT-IoT-v3\data\NF-BoT-IoT-v3.csv'),
    ('NF-CICIDS2018-v3',   r'v3-Datasets\NF-CICIDS2018-v3\data\NF-CICIDS2018-v3.csv'),
    ('NF-ToN-IoT-v3',      r'v3-Datasets\NF-ToN-IoT-v3\data\NF-ToN-IoT-v3.csv'),
    ('NF-UNSW-NB15-v3',    r'v3-Datasets\NF-UNSW-NB15-v3\data\NF-UNSW-NB15-v3.csv'),
]
```

| Dataset          | Rows   | Attack Types                                                                          |
| ---------------- | ------ | ------------------------------------------------------------------------------------- |
| NF-BoT-IoT-v3    | ~16.9M | DoS, DDoS, Reconnaissance, Theft                                                      |
| NF-CICIDS2018-v3 | ~20.1M | DoS variants, DDoS, BruteForce, Bot, Infiltration, Web attacks                        |
| NF-ToN-IoT-v3    | ~27.5M | ddos, xss, password, scanning, injection, dos, backdoor, mitm, ransomware             |
| NF-UNSW-NB15-v3  | ~2.3M  | Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode, Worms |

## ATT&CK Mapping (Reuse from run_classification.py)

```python
# Reuse the validated mapping_dict from run_classification.py
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
```

## Feature Selection (18 features from NetFlow v3 schema)

The v3-Datasets already provide rich numeric features. Instead of hand-crafting 12 features from raw Zeek fields, we **select and transform** from the existing 46 numeric columns.

### Tier 1: Direct Use (log-scaled for heavy tails)

```python
# Volume — log1p to handle heavy tails
'log1p_IN_BYTES',
'log1p_OUT_BYTES',
'log1p_IN_PKTS',
'log1p_OUT_PKTS',

# Temporal
'log1p_FLOW_DURATION_MILLISECONDS',

# Throughput
'log1p_SRC_TO_DST_SECOND_BYTES',
'log1p_DST_TO_SRC_SECOND_BYTES',
```

### Tier 2: Derived Ratios

```python
# Directional asymmetry (key for exfil vs C2 vs recon)
'bytes_ratio',        # IN_BYTES / (OUT_BYTES + 1)
'pkts_ratio',         # IN_PKTS / (OUT_PKTS + 1)

# Retransmission rate (indicator of evasion, scanning, DoS)
'retransmit_ratio',   # (RETRANSMITTED_IN_PKTS + RETRANSMITTED_OUT_PKTS)
                      #   / (IN_PKTS + OUT_PKTS + 1)
```

### Tier 3: Packet-Size Distribution (attack fingerprints)

```python
# Normalized packet-size bins (sum to 1 per flow)
'pkt_frac_up_to_128',    # NUM_PKTS_UP_TO_128_BYTES / total_pkts
'pkt_frac_128_to_256',
'pkt_frac_256_to_512',
'pkt_frac_512_to_1024',
'pkt_frac_1024_to_1514',
```

### Tier 4: Protocol & Port (categorical → numeric)

```python
# Port category (0=well-known, 1=registered, 2=dynamic)
'src_port_category',  # from L4_SRC_PORT
'dst_port_category',  # from L4_DST_PORT

# Protocol (direct numeric, already encoded in NetFlow v3)
'PROTOCOL',
```

### Feature Extractor Implementation

```python
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Columns to drop before HMM (leakage or non-numeric)
DROP_COLS = [
    'IPV4_SRC_ADDR', 'IPV4_DST_ADDR',
    'FLOW_START_MILLISECONDS', 'FLOW_END_MILLISECONDS',
    'Label', 'Attack',
]

def extract_hmm_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract and transform 18 HMM features from NetFlow v3 DataFrame."""
    f = pd.DataFrame(index=df.index)

    # Tier 1: Log-scaled volume and temporal
    for col in ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS',
                'FLOW_DURATION_MILLISECONDS',
                'SRC_TO_DST_SECOND_BYTES', 'DST_TO_SRC_SECOND_BYTES']:
        f[f'log1p_{col}'] = np.log1p(df[col].clip(lower=0))

    # Tier 2: Directional ratios
    f['bytes_ratio'] = df['IN_BYTES'] / (df['OUT_BYTES'] + 1)
    f['pkts_ratio'] = df['IN_PKTS'] / (df['OUT_PKTS'] + 1)
    total_pkts = df['IN_PKTS'] + df['OUT_PKTS'] + 1
    retrans = df['RETRANSMITTED_IN_PKTS'] + df['RETRANSMITTED_OUT_PKTS']
    f['retransmit_ratio'] = retrans / total_pkts

    # Tier 3: Packet-size distribution (normalized fractions)
    size_cols = [
        'NUM_PKTS_UP_TO_128_BYTES', 'NUM_PKTS_128_TO_256_BYTES',
        'NUM_PKTS_256_TO_512_BYTES', 'NUM_PKTS_512_TO_1024_BYTES',
        'NUM_PKTS_1024_TO_1514_BYTES',
    ]
    pkt_total = df[size_cols].sum(axis=1).clip(lower=1)
    for col in size_cols:
        short_name = col.replace('NUM_PKTS_', 'pkt_frac_').lower()
        f[short_name] = df[col] / pkt_total

    # Tier 4: Port categories + protocol
    f['src_port_category'] = pd.cut(
        df['L4_SRC_PORT'],
        bins=[-1, 1023, 49151, 65535],
        labels=[0, 1, 2]
    ).astype(float)
    f['dst_port_category'] = pd.cut(
        df['L4_DST_PORT'],
        bins=[-1, 1023, 49151, 65535],
        labels=[0, 1, 2]
    ).astype(float)
    f['PROTOCOL'] = df['PROTOCOL'].astype(float)

    return f.replace([np.inf, -np.inf], np.nan).fillna(0)
```

## Session Building (Adapted for NetFlow v3)

NetFlow v3 has explicit `FLOW_START_MILLISECONDS` and `FLOW_END_MILLISECONDS`. Sessions are built by:

1.  Grouping flows by `(IPV4_SRC_ADDR, IPV4_DST_ADDR)` pair
2.  Sorting by `FLOW_START_MILLISECONDS` within each group
3.  Splitting at gaps > 30 minutes (1,800,000 ms)
4.  Filtering sessions with \< 3 flows (too short for HMM)

```python
def build_sessions(df: pd.DataFrame, gap_ms: int = 1_800_000, min_flows: int = 3):
    """Build flow sequences grouped by (src, dst) IP pair with gap splitting."""
    df = df.sort_values('FLOW_START_MILLISECONDS')

    sessions = []
    for (src, dst), group in df.groupby(['IPV4_SRC_ADDR', 'IPV4_DST_ADDR']):
        times = group['FLOW_START_MILLISECONDS'].values
        gaps = np.diff(times)
        split_points = np.where(gaps > gap_ms)[0] + 1
        sub_sessions = np.split(group.index.values, split_points)

        for idx_arr in sub_sessions:
            if len(idx_arr) >= min_flows:
                sessions.append({
                    'src_ip': src,
                    'dst_ip': dst,
                    'flow_indices': idx_arr,
                    'n_flows': len(idx_arr),
                })
    return sessions
```

## State-to-MITRE Mapping Strategy

After training, analyze each state's emission distribution and map to MITRE tactics using the v3 feature signatures:

| MITRE Tactic        | Expected v3 Signature                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------- |
| Reconnaissance      | Low bytes, short duration, high `pkt_frac_up_to_128`, many unique dst_ports, low `retransmit_ratio` |
| Initial_Access      | Inbound-heavy `bytes_ratio`, dst_port in well-known range (80, 443, 22), moderate duration          |
| Credential_Access   | Auth ports (22, 3389, 21), repeated short flows, high `retransmit_ratio`, low `bytes_ratio`         |
| Lateral_Movement    | Internal IP pairs, varied dst_ports, moderate bytes, mixed packet sizes                             |
| Exfiltration        | Very high `bytes_ratio` (outbound >> inbound), long duration, large `pkt_frac_1024_to_1514`         |
| Command_and_Control | Regular IAT intervals, medium duration, single dst_port, low `bytes_ratio`                          |
| Impact (DoS/DDoS)   | Very high pkts/bytes, short flows, near-zero `bytes_ratio`, `pkt_frac_up_to_128` dominant           |
| Persistence         | Low volume, periodic patterns, specific dst_ports                                                   |
| Defense_Evasion     | Anomalous TTL, encrypted protocols (L7_PROTO), fragmented packet sizes                              |
| Execution           | Medium duration, injection-like payload sizes, specific L7 protocols                                |
| Discovery           | Similar to Reconnaissance but internal targets, varied protocols                                    |

## File Structure

```
scripts/hmm_v3/
├── requirements.txt          # hmmlearn, scikit-learn, pandas, numpy
├── config.py                 # Configuration: paths, constants, mapping_dict
│
├── data/
│   ├── loader.py             # CSV loading with chunked sampling
│   └── session_builder.py    # Flow sequence segmentation (IP pairs + gap)
│
├── features/
│   └── extractor.py          # extract_hmm_features() — 18 features from v3
│
├── model/
│   ├── hmm.py                # AttackPhaseHMM class
│   ├── model_selection.py    # BIC-based K selection
│   └── persistence.py        # joblib save/load
│
├── interpretation/
│   ├── state_analyzer.py     # State signature computation
│   └── mitre_mapper.py       # State-to-MITRE mapping rules
│
├── validation/               # NEW: uses ground-truth labels
│   ├── metrics.py            # ARI, NMI, purity, confusion matrix
│   └── compare.py            # HMM states vs Attack labels per dataset
│
├── cli/
│   ├── train.py              # python -m hmm_v3.cli.train --dataset NF-BoT-IoT-v3
│   ├── label.py              # python -m hmm_v3.cli.label --dataset NF-BoT-IoT-v3
│   ├── evaluate.py           # python -m hmm_v3.cli.evaluate --dataset NF-BoT-IoT-v3
│   └── train_all.py          # Train on all 4 datasets sequentially
│
└── tests/
    └── test_*.py             # Unit tests
```

## Implementation Phases

### Phase 1: Data Pipeline (TDD)

1.  Write tests for CSV loader (chunked reading, sampling at `MAX_PER_CLASS=50_000`)
2.  Implement `load_v3_dataset()` — reuse `datasets_info` and `mapping_dict` from `run_classification.py`
3.  Write tests for session builder (gap detection, min length, IP-pair grouping)
4.  Implement `build_sessions()`
5.  Write tests for feature extractor (log scaling, ratios, packet-size fractions, port categories)
6.  Implement `extract_hmm_features()`

### Phase 2: HMM Core (TDD)

1.  Write tests for HMM training (convergence, state count)
2.  Implement `AttackPhaseHMM.fit()` and `.predict_states()`
3.  Write tests for Viterbi decoding on synthetic sequences
4.  Implement model persistence (save/load with joblib)
5.  Implement BIC-based model selection (K = 6..15)

### Phase 3: State Interpretation

1.  Implement state signature computation (mean/std of each feature per state)
2.  Define MITRE tactic signature profiles using v3 features
3.  Implement matching algorithm with confidence scores
4.  Analyze transition matrix for kill chain paths

### Phase 4: Validation (NEW — leverages v3 ground truth)

1.  For each dataset, map `Attack` → `MITRE_Tactic` using `mapping_dict`
2.  Compute cluster-vs-label metrics:
    - **Adjusted Rand Index (ARI)**: Measures agreement between HMM states and ground truth
    - **Normalized Mutual Information (NMI)**: How much knowing HMM state tells you about the true tactic
    - **Purity**: Fraction of flows in each HMM state that match the dominant tactic
3.  Generate confusion matrix: HMM state (rows) vs ground-truth MITRE tactic (columns)
4.  Per-dataset comparison + combined cross-dataset analysis
5.  Output charts to `Charts/` directory following existing project pattern

### Phase 5: CLI & Integration

1.  Build train/label/evaluate CLI commands accepting `--dataset` flag
2.  `train_all.py` — iterate over all 4 datasets, train separate models + one combined
3.  Output labeled CSVs with `HMM_STATE`, `HMM_TACTIC`, `CONFIDENCE` columns appended
4.  Save charts to `Charts/` directory (consistent with `run_classification.py`)

## Dependencies

```
# scripts/hmm_v3/requirements.txt
hmmlearn>=0.3.0
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
joblib>=1.3.0
matplotlib>=3.7.0
seaborn>=0.12.0
```

Note: No `pyarrow` or `duckdb` needed — v3-Datasets are CSV, loaded with pandas.

## Usage

```
# Train on a single dataset
python -m hmm_v3.cli.train --dataset NF-BoT-IoT-v3 \
    --output models/hmm_bot_iot.pkl \
    --select-k  # BIC to find optimal states

# Train on all datasets (per-dataset + combined)
python -m hmm_v3.cli.train_all \
    --output-dir models/ \
    --select-k

# Label flows
python -m hmm_v3.cli.label --dataset NF-BoT-IoT-v3 \
    --model models/hmm_bot_iot.pkl \
    --output data/NF-BoT-IoT-v3-hmm-labeled.csv

# Evaluate against ground truth
python -m hmm_v3.cli.evaluate --dataset NF-BoT-IoT-v3 \
    --model models/hmm_bot_iot.pkl
```

## Success Metrics

### Internal Quality

- Silhouette score > 0.3 on feature space
- All states utilized (no empty states)
- BIC converges (clear elbow in K search)

### Interpretability

- ≥6 states map clearly to MITRE tactics with confidence > 0.6
- Transition matrix shows expected kill chain progressions

### Validation Against Ground Truth (NEW)

- **ARI > 0.3** vs ground-truth MITRE_Tactic labels (higher bar than Zeek since we have labels)
- **NMI > 0.3** — mutual information between HMM states and true tactics
- **Per-state purity > 0.6** — each HMM state is dominated by one MITRE tactic
- Cross-dataset consistency: same state index maps to similar tactics across datasets

## Config (config.py)

```python
import os

BASE_DIR = r'c:\Users\josia\Documents\Kill Chain Research'
V3_DIR = os.path.join(BASE_DIR, 'v3-Datasets')
CHARTS_DIR = os.path.join(BASE_DIR, 'Charts')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

os.makedirs(CHARTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

MAX_PER_CLASS = 50_000  # Match run_classification.py sampling

DATASETS_INFO = [
    ('NF-BoT-IoT-v3',   os.path.join(V3_DIR, 'NF-BoT-IoT-v3', 'data', 'NF-BoT-IoT-v3.csv')),
    ('NF-CICIDS2018-v3', os.path.join(V3_DIR, 'NF-CICIDS2018-v3', 'data', 'NF-CICIDS2018-v3.csv')),
    ('NF-ToN-IoT-v3',   os.path.join(V3_DIR, 'NF-ToN-IoT-v3', 'data', 'NF-ToN-IoT-v3.csv')),
    ('NF-UNSW-NB15-v3', os.path.join(V3_DIR, 'NF-UNSW-NB15-v3', 'data', 'NF-UNSW-NB15-v3.csv')),
]

DROP_COLS = [
    'IPV4_SRC_ADDR', 'IPV4_DST_ADDR',
    'FLOW_START_MILLISECONDS', 'FLOW_END_MILLISECONDS',
    'Label', 'Attack',
]

SESSION_GAP_MS = 1_800_000   # 30 minutes
SESSION_MIN_FLOWS = 3
HMM_K_RANGE = range(6, 16)  # Search 6–15 states
HMM_N_ITER = 100             # Max EM iterations
HMM_RANDOM_STATE = 42
```

## Critical Files (Existing Project Context)

- `run_classification.py` — ATT&CK mapping dict, dataset paths, sampling pattern to reuse
- `run_port_correlation_analysis.py` — Port-category logic, well-known port definitions
- `v3-Datasets/*/data/NetFlow_v3_Features.csv` — 54-column schema definition
- `v3-Datasets/*/data/*.csv` — Raw training data (~66.9M flows total)

## Verification

1.  Unit tests: `pytest scripts/hmm_v3/tests/`
2.  Train on NF-UNSW-NB15-v3 first (smallest at ~2.3M, fastest iteration)
3.  Inspect learned state signatures — do they match expected MITRE profiles?
4.  Compare transition matrix to expected kill chain order
5.  **Validate against ground truth**: ARI, NMI, purity vs `Attack` labels
6.  Repeat for all 4 datasets, then train combined model
7.  Compare per-dataset vs combined model performance
8.  Save all charts to `Charts/` following project conventions
