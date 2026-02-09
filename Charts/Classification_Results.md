# Classification Results: MITRE ATT&CK Tactic Prediction

## Dataset Summary

- **Combined samples (before sampling):** ~66.9M
- **Sampled for training/testing:** 930,228
- **MAX_PER_CLASS:** 50,000 per tactic per dataset
- **Train/Test split:** 80/20 stratified
- **Features used:** 49 (all NetFlow v3 features minus IPs and timestamps)

## Stage 1: Binary Classification (Benign vs Malicious)

| Config             | Macro F1 | MCC    | Time (s) |
| ------------------ | -------- | ------ | -------- |
| Config_A_Baseline  | 0.9072   | 0.8255 | 68.5     |
| Config_B_DeepTrees | 0.9112   | 0.8324 | 121.0    |
| Config_C_MoreTrees | 0.9131   | 0.8360 | 381.1    |

**Best:** Config_C_MoreTrees (Macro F1=0.9131)

## Stage 2: Multi-class ATT&CK Tactic Classification

| Config             | Macro F1 | Weighted F1 | MCC    | Time (s) |
| ------------------ | -------- | ----------- | ------ | -------- |
| Config_A_Baseline  | 0.9013   | 0.9386      | 0.9195 | 344.7    |
| Config_B_DeepTrees | 0.9071   | 0.9423      | 0.9270 | 1459.2   |
| Config_C_MoreTrees | 0.9095   | 0.9434      | 0.9297 | 2287.6   |

**Best:** Config_C_MoreTrees (Macro F1=0.9095)

## Best Model: Per-class Report

| ATT&CK Tactic       | Precision | Recall | F1-Score | Support |
| ------------------- | --------- | ------ | -------- | ------- |
| Command_and_Control | 1.0000    | 1.0000 | 1.0000   | 10,000  |
| Credential_Access   | 0.9644    | 0.9679 | 0.9661   | 23,930  |
| Defense_Evasion     | 0.2488    | 0.6172 | 0.3546   | 1,408   |
| Discovery           | 0.9978    | 0.9964 | 0.9971   | 10,000  |
| Execution           | 0.9664    | 0.9599 | 0.9631   | 10,000  |
| Exfiltration        | 0.9938    | 0.9969 | 0.9954   | 323     |
| Impact              | 0.9525    | 0.8988 | 0.9249   | 37,991  |
| Initial_Access      | 0.8751    | 0.8838 | 0.8794   | 18,734  |
| Lateral_Movement    | 0.9961    | 0.9994 | 0.9978   | 10,000  |
| Persistence         | 0.9999    | 0.9992 | 0.9995   | 10,000  |
| Reconnaissance      | 0.9320    | 0.9210 | 0.9265   | 13,660  |

## Parameter Configurations

### Config_A_Baseline

| Parameter         | Value |
| ----------------- | ----- |
| boosting_type     | gbdt  |
| num_leaves        | 31    |
| learning_rate     | 0.1   |
| n_estimators      | 200   |
| max_depth         | \-1   |
| min_child_samples | 20    |
| subsample         | 0.8   |
| colsample_bytree  | 0.8   |
| reg_alpha         | 0.0   |
| reg_lambda        | 0.0   |

### Config_B_DeepTrees

| Parameter         | Value |
| ----------------- | ----- |
| boosting_type     | gbdt  |
| num_leaves        | 63    |
| learning_rate     | 0.05  |
| n_estimators      | 400   |
| max_depth         | 12    |
| min_child_samples | 10    |
| subsample         | 0.7   |
| colsample_bytree  | 0.7   |
| reg_alpha         | 0.1   |
| reg_lambda        | 0.1   |

### Config_C_MoreTrees

| Parameter         | Value |
| ----------------- | ----- |
| boosting_type     | gbdt  |
| num_leaves        | 127   |
| learning_rate     | 0.03  |
| n_estimators      | 600   |
| max_depth         | 15    |
| min_child_samples | 5     |
| subsample         | 0.6   |
| colsample_bytree  | 0.6   |
| reg_alpha         | 1.0   |
| reg_lambda        | 1.0   |

## Top 20 Features

| Rank | Feature                    | Importance |
| ---- | -------------------------- | ---------- |
| 1    | L4_SRC_PORT                | 74,502     |
| 2    | L4_DST_PORT                | 29,975     |
| 3    | LONGEST_FLOW_PKT           | 26,754     |
| 4    | IN_BYTES                   | 23,996     |
| 5    | SRC_TO_DST_AVG_THROUGHPUT  | 23,023     |
| 6    | SRC_TO_DST_IAT_MAX         | 19,737     |
| 7    | DST_TO_SRC_AVG_THROUGHPUT  | 19,525     |
| 8    | FLOW_DURATION_MILLISECONDS | 19,330     |
| 9    | SRC_TO_DST_SECOND_BYTES    | 19,177     |
| 10   | DNS_QUERY_ID               | 18,602     |
| 11   | DST_TO_SRC_SECOND_BYTES    | 18,501     |
| 12   | ICMP_TYPE                  | 18,008     |
| 13   | L7_PROTO                   | 17,621     |
| 14   | DST_TO_SRC_IAT_MAX         | 16,932     |
| 15   | OUT_BYTES                  | 16,444     |
| 16   | SRC_TO_DST_IAT_AVG         | 15,015     |
| 17   | SRC_TO_DST_IAT_STDDEV      | 14,988     |
| 18   | DST_TO_SRC_IAT_AVG         | 14,627     |
| 19   | DST_TO_SRC_IAT_STDDEV      | 14,387     |
| 20   | TCP_WIN_MAX_IN             | 13,799     |
