# ML Model Analysis for MITRE ATT&CK Tactic Classification

## Combined Dataset Classification Challenge

### Problem Characteristics

| Property          | Value                                 |
| ----------------- | ------------------------------------- |
| Total samples     | 66,935,021                            |
| Number of classes | 12 (11 ATT&CK tactics + Benign)       |
| Features          | 46 numeric NetFlow features           |
| Imbalance ratio   | **13,128:1** (Impact vs Exfiltration) |
| Smallest class    | Exfiltration: 1,615 samples           |
| Largest class     | Benign: 36.6M samples                 |

### Combined MITRE ATT&CK Tactic Distribution

| ATT&CK Tactic       | Count      | Percentage |
| ------------------- | ---------- | ---------- |
| Benign (-)          | 36,596,560 | 54.67%     |
| Impact              | 21,201,025 | 31.67%     |
| Initial_Access      | 2,878,103  | 4.30%      |
| Credential_Access   | 2,197,253  | 3.28%      |
| Reconnaissance      | 1,713,432  | 2.56%      |
| Discovery           | 1,358,977  | 2.03%      |
| Execution           | 381,777    | 0.57%      |
| Command_and_Control | 207,703    | 0.31%      |
| Persistence         | 203,384    | 0.30%      |
| Lateral_Movement    | 188,152    | 0.28%      |
| Defense_Evasion     | 7,040      | 0.01%      |
| Exfiltration        | 1,615      | 0.00%      |

This is a large-scale, severely imbalanced, multi-class tabular classification problem.

---

## Model Comparison

### 1\. LightGBM (Recommended)

**Why it's the best fit:**

- Specifically designed for large-scale tabular data — handles 67M samples efficiently with histogram-based splitting
- Native `class_weight='balanced'` and `scale_pos_weight` for imbalance
- Leaf-wise tree growth captures complex decision boundaries
- Fast training (minutes, not hours) even at this scale
- Low memory footprint compared to alternatives
- Excellent out-of-the-box performance on network traffic data (widely used in IDS literature)

**Weaknesses:** Less effective if features have complex sequential/temporal dependencies.

---

### 2\. XGBoost

**Pros:** Strong accuracy, good regularization (L1/L2), supports GPU training, sample weighting for imbalance.

**Cons:** Level-wise growth is slower than LightGBM at 67M samples. Training time will be significantly longer. Comparable accuracy to LightGBM in most IDS benchmarks.

---

### 3\. CatBoost

**Pros:** Handles categorical features natively (useful if you encode IP addresses as categories), ordered boosting reduces overfitting, good with imbalanced data.

**Cons:** Slower than LightGBM on this scale. Less commonly used in IDS literature.

---

### 4\. Random Forest

**Pros:** Simple, parallelizable, interpretable (feature importance), robust to overfitting.

**Cons:** Memory-intensive at 67M samples (stores all trees fully). Slower inference. Tends to underperform gradient boosting on imbalanced data. Would need aggressive subsampling.

---

### 5\. Deep Neural Networks (MLP / 1D-CNN)

**Pros:** Can learn non-linear feature interactions. Autoencoders can help with representation learning for rare classes. Can be combined with SMOTE in latent space.

**Cons:** Tabular data consistently underperforms tree-based methods in benchmarks. Requires more hyperparameter tuning, normalization, and longer training. Harder to interpret. No inherent advantage at this scale for structured features.

---

### 6\. SVM

**Not recommended.** O(n^2) to O(n^3) complexity makes it infeasible for 67M samples without heavy subsampling, which would destroy rare class representation.

---

## Recommended Strategy

### Primary Model: LightGBM with Hierarchical Classification

Given the 13,128:1 imbalance, a single flat classifier will likely ignore rare classes. Consider a two-stage approach:

```
Stage 1: Binary classifier (Benign vs Malicious)
Stage 2: Multi-class classifier (11 ATT&CK tactics, trained on malicious traffic only)
```

### Handling the Imbalance

| Technique                   | Application                                                                         |
| --------------------------- | ----------------------------------------------------------------------------------- |
| **Class weights**           | `class_weight='balanced'` in LightGBM — inversely proportional to class frequency   |
| **Stratified sampling**     | Undersample majority (Impact) + oversample minority (Exfiltration, Defense_Evasion) |
| **SMOTE / ADASYN**          | Synthetic oversampling for classes \< 10K samples                                   |
| **Focal Loss**              | Custom loss function that down-weights easy (majority) examples                     |
| **Ensemble of specialists** | Train separate one-vs-rest models for rare classes                                  |

### Evaluation Metrics

Do **not** use accuracy (a model predicting "Benign" always gets 54.67%). Instead use:

- **Macro F1-score** — treats all classes equally regardless of size
- **Per-class precision/recall** — critical for rare classes
- **Confusion matrix** — to see where misclassifications occur
- **Matthews Correlation Coefficient (MCC)** — robust to imbalance

### Cross-Dataset Generalization

Since the four datasets come from different network environments, consider:

- **Leave-one-dataset-out cross-validation** — train on 3 datasets, test on the 4th
- **Domain adaptation** — normalize features per dataset before combining
- **Feature importance analysis** — verify the model isn't learning dataset-specific artifacts (e.g., IP address patterns)

---

## Summary Recommendation

| Aspect         | Recommendation                                                                         |
| -------------- | -------------------------------------------------------------------------------------- |
| **Model**      | LightGBM (primary), XGBoost (validation)                                               |
| **Strategy**   | Two-stage: binary then multi-class                                                     |
| **Imbalance**  | Class weights + stratified sampling + SMOTE for tail classes                           |
| **Evaluation** | Macro F1, per-class recall, MCC                                                        |
| **Validation** | Stratified K-fold + leave-one-dataset-out                                              |
| **Features**   | Drop IP addresses and timestamps (leakage risk), use all 43 remaining NetFlow features |
