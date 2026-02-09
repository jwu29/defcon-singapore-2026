# HackAPrompt Dataset — Analysis Summary

## 1\. Dataset Overview

- **Raw rows**: 601,757
- **Cleaned rows**: 546,301
- **Rows removed**: 55,456
- **Columns**: 13
- **Models**: gpt-3.5-turbo, FlanT5-XXL, text-davinci-003
- **Challenge levels**: \[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10\]

### Cleaning Steps

- Dropped 30332 exact duplicate rows
- Dropped 25124 rows missing critical fields (\['user_input', 'prompt', 'completion', 'model', 'level'\])
- Filled missing 'score' values with 0
- Enforced correct dtypes for level, correct, error, token_count, timestamp
- Removed 0 rows where error == True
- Stripped whitespace from 7 string columns

## 2\. Submission Distribution

### Submissions per Level

| Level | Count  |
| ----- | ------ |
| 0     | 32,933 |
| 1     | 58,098 |
| 2     | 62,613 |
| 3     | 22,237 |
| 4     | 63,297 |
| 5     | 54,378 |
| 6     | 45,334 |
| 7     | 89,760 |
| 8     | 36,531 |
| 9     | 69,284 |
| 10    | 11,836 |

### Submissions per Model

| Model            | Count   |
| ---------------- | ------- |
| gpt-3.5-turbo    | 275,948 |
| FlanT5-XXL       | 217,262 |
| text-davinci-003 | 53,091  |

### Dataset Source Split

| Source          | Count   |
| --------------- | ------- |
| playground_data | 535,037 |
| submission_data | 11,264  |

## 3\. Success Rate Analysis

### Success Rate per Level

| Level | Success Rate (%) |
| ----- | ---------------- |
| 0     | 11.15%           |
| 1     | 11.31%           |
| 2     | 15.64%           |
| 3     | 22.87%           |
| 4     | 8.95%            |
| 5     | 9.48%            |
| 6     | 6.83%            |
| 7     | 4.74%            |
| 8     | 11.25%           |
| 9     | 3.67%            |
| 10    | 0.00%            |

### Success Rate by Level x Model

See `success_rate_heatmap.png` for the full matrix.

## 4\. Token Count Analysis

### Token Count by Success/Failure

- **Successful attempts** — Mean: 56.6, Median: 27.0
- **Failed attempts** — Mean: 123.6, Median: 26.0

## 5\. Temporal Analysis

- **Date range**: 2023-05-05 to 2023-06-10
- See `submissions_over_time.png` and `success_rate_over_time.png`.

## 6\. Output Files

| File                              | Description                        |
| --------------------------------- | ---------------------------------- |
| `cleaned_hackaprompt.csv`         | Cleaned dataset                    |
| `submissions_per_level.png`       | Bar chart of submissions per level |
| `submissions_per_model.png`       | Bar chart of submissions per model |
| `dataset_source_split.png`        | Pie chart of data sources          |
| `success_rate_per_level.png`      | Success rate by level              |
| `success_rate_by_level_model.png` | Grouped bar chart by level & model |
| `success_rate_heatmap.png`        | Heatmap of success rates           |
| `token_count_by_level.png`        | Box plot of token counts by level  |
| `token_count_success_vs_fail.png` | Violin plot: success vs failure    |
| `token_vs_level_scatter.png`      | Scatter plot: tokens vs level      |
| `submissions_over_time.png`       | Daily submission counts            |
| `success_rate_over_time.png`      | Success rate trend over time       |
