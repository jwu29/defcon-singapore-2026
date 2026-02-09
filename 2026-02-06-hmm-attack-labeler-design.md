# Unsupervised HMM-Based MITRE ATT&CK Labeling Tool

## Overview

Build an unsupervised Hidden Markov Model tool that discovers attack phases from network flow sequences without using existing labels, then maps learned states to MITRE ATT&CK tactics.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     HMM Flow Labeler Pipeline                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Parquet Data ──▶ Session Builder ──▶ Feature Extractor        │
│       │               │                      │                  │
│       │          (by src_ip,            (12 features,           │
│       │           30min gaps)            normalized)            │
│       │               │                      │                  │
│       ▼               ▼                      ▼                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  Gaussian HMM (hmmlearn)                 │   │
│  │  - 10 hidden states (or BIC-selected)                   │   │
│  │  - Baum-Welch unsupervised training                     │   │
│  │  - Viterbi decoding for labeling                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              State Interpreter                           │   │
│  │  - Compute state signatures (bytes, ports, duration)    │   │
│  │  - Match to MITRE tactic profiles                       │   │
│  │  - Analyze transition matrix for kill chain paths       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  Output: Labeled parquet with HMM_STATE, HMM_TACTIC, CONFIDENCE│
└─────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Model type | Gaussian HMM | Flow features are continuous; handles multimodal distributions |
| Library | hmmlearn | Well-maintained, scikit-learn compatible |
| States | 10 (with BIC selection) | Covers key MITRE tactics + benign + transitional |
| Sequence def | Per source IP, 30min gap boundary | Matches existing kill chain logic |
| Features | 12 core features | Volume, temporal, protocol, port behavior |

## Feature Selection (12 features)

```python
features = [
    # Volume (log-scaled for heavy tails)
    'log1p_in_bytes', 'log1p_out_bytes',
    'log1p_in_pkts', 'log1p_out_pkts',

    # Temporal
    'log1p_duration_ms', 'log1p_iat_avg',

    # Derived ratios
    'bytes_ratio',      # IN_BYTES / (OUT_BYTES + 1)
    'pkts_per_second',  # packets / duration

    # Protocol (one-hot)
    'is_tcp', 'is_udp', 'is_icmp',

    # Port category (0=well-known, 1=registered, 2=ephemeral)
    'port_category',
]
```

## State-to-MITRE Mapping Strategy

After training, analyze each state's emission distribution:

| MITRE Tactic | Expected Signature |
|--------------|-------------------|
| Reconnaissance | Low bytes, short duration, many ports, failed connections |
| Initial Access | More inbound bytes, HTTP/SSH services |
| Credential Access | Auth ports (22, 3389), repeated attempts |
| Lateral Movement | Internal IPs, varied ports |
| Exfiltration | High bytes_ratio (outbound >> inbound), long duration |
| Command & Control | Regular intervals, medium duration, single port |

## File Structure

```
scripts/hmm/
├── requirements.txt          # hmmlearn, scikit-learn, pandas, pyarrow
├── config.py                 # Configuration constants
│
├── data/
│   ├── loader.py             # Parquet loading with DuckDB
│   └── session_builder.py    # Flow sequence segmentation
│
├── features/
│   ├── extractor.py          # Feature extraction pipeline
│   └── normalizer.py         # StandardScaler, encoding
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
├── cli/
│   ├── train.py              # python -m hmm.cli.train data.parquet
│   ├── label.py              # python -m hmm.cli.label flows.parquet
│   └── evaluate.py           # python -m hmm.cli.evaluate
│
└── tests/
    └── test_*.py             # Unit tests
```

## Implementation Phases

### Phase 1: Data Pipeline (TDD)
1. Write tests for session builder (gap detection, min length)
2. Implement `SessionBuilder.build_sessions()`
3. Write tests for feature extractor (log scaling, one-hot encoding)
4. Implement `FlowFeatureExtractor.transform()`

### Phase 2: HMM Core (TDD)
1. Write tests for HMM training (convergence, state count)
2. Implement `AttackPhaseHMM.fit()` and `.predict_states()`
3. Write tests for Viterbi decoding
4. Implement model persistence (save/load)

### Phase 3: State Interpretation
1. Implement state signature computation
2. Define MITRE tactic signature profiles
3. Implement matching algorithm with confidence scores
4. Analyze transition matrix for kill chain paths

### Phase 4: CLI & Integration
1. Build train/label/evaluate CLI commands
2. Output labeled parquet files
3. (Optional) Add TypeScript queries for HMM-labeled sessions

## Dependencies

```
# scripts/hmm/requirements.txt
hmmlearn>=0.3.0
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
pyarrow>=14.0.0
duckdb>=0.9.0
joblib>=1.3.0
```

## Usage

```bash
# Train model
python -m hmm.cli.train data/UWF-ZeekData24.parquet \
    --output models/attack_hmm.pkl \
    --select-k  # Use BIC to find optimal states

# Label flows
python -m hmm.cli.label data/UWF-ZeekData24.parquet \
    --model models/attack_hmm.pkl \
    --output data/UWF-ZeekData24-hmm-labeled.parquet

# Evaluate
python -m hmm.cli.evaluate --model models/attack_hmm.pkl
```

## Success Metrics

- **Internal**: Silhouette score > 0.3, all states utilized
- **Interpretability**: ≥6 states map clearly to MITRE tactics
- **Transitions**: Matrix shows expected kill chain paths
- **Optional validation**: ARI > 0.4 vs ground truth labels

## Critical Files

- `src/lib/schema.ts` - Flow schema and MITRE tactics to align with
- `scripts/convert-zeekdata24.py` - Pattern for Python data processing
- `data/UWF-ZeekData24.parquet` - Training data (~1.9M flows)

## Frontend Integration (Full UI)

### New Components

```
src/components/hmm/
├── HMMPanel.tsx              # Main container, toggle between views
├── StateExplorer.tsx         # Browse learned states with signatures
├── TransitionMatrix.tsx      # Heatmap of state transitions (kill chain paths)
├── HMMTimeline.tsx           # Timeline with HMM states instead of ground truth
└── ConfidenceIndicator.tsx   # Visual confidence badge per flow/session
```

### New TypeScript Types

```typescript
// src/lib/hmm/types.ts
interface HMMState {
  state_id: number;
  tactic: string;           // Mapped MITRE tactic
  confidence: number;       // Mapping confidence 0-1
  signature: StateSignature;
}

interface StateSignature {
  avg_in_bytes: number;
  avg_out_bytes: number;
  bytes_ratio: number;
  avg_duration_ms: number;
  top_ports: Record<number, number>;
  conn_state_dist: Record<string, number>;
}

interface HMMSession extends AttackSession {
  hmm_tactics: string[];    // HMM-predicted tactics
  avg_confidence: number;   // Average prediction confidence
}
```

### New Queries

```typescript
// src/lib/motherduck/queries/hmm.ts

// Get sessions with HMM labels
getHMMSessions(minConfidence: number, limit: number): HMMSession[]

// Get state distribution across all flows
getHMMStateDistribution(): { state_id: number, tactic: string, count: number }[]

// Get transition counts between states (for matrix visualization)
getHMMTransitions(): { from_state: number, to_state: number, count: number }[]
```

### UI Flow

1. **HMMPanel** in ForensicDashboard (new tab alongside "Chat" and "Kill Chain")
2. **StateExplorer**: Cards showing each learned state with signature details
3. **TransitionMatrix**: D3/Recharts heatmap showing state→state transition probabilities
4. **HMMTimeline**: Similar to KillChainTimeline but using HMM_TACTIC column
5. **ConfidenceIndicator**: Color-coded badge (green >0.8, yellow 0.5-0.8, red <0.5)

### Implementation Order

1. Python HMM tool (Phases 1-4 from above)
2. TypeScript types and queries
3. HMMTimeline (reuse KillChainTimeline patterns)
4. StateExplorer component
5. TransitionMatrix visualization
6. ConfidenceIndicator integration

## Verification

1. Run unit tests: `pytest scripts/hmm/tests/`
2. Train on UWF dataset and verify convergence
3. Inspect learned state signatures
4. Compare transition matrix to expected kill chain order
5. (Optional) Compare HMM labels to ground truth MITRE_TACTIC
6. **UI tests**: Load HMM-labeled parquet, verify HMMPanel displays correctly
7. **E2E**: Click through StateExplorer → filter flows by state → verify results
