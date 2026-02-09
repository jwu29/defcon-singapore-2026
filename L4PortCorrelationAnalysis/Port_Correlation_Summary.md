# L4 Port Correlation Analysis Summary

## Overview

This analysis examines the correlation between L4 (transport layer) ports  
(L4_SRC_PORT and L4_DST_PORT) and attack labels across all four datasets.

## Correlation Metrics

| Dataset          | Port        | Chi      | p-value   | Cramer's V | Interpretation       |
| ---------------- | ----------- | -------- | --------- | ---------- | -------------------- |
| NF-BoT-IoT-v3    | L4_SRC_PORT | 3292.68  | 0.00e+00  | 0.1283     | Weak association     |
| NF-BoT-IoT-v3    | L4_DST_PORT | 86233.60 | 0.00e+00  | 0.6566     | Strong association   |
| NF-CICIDS2018-v3 | L4_SRC_PORT | 9301.19  | 0.00e+00  | 0.2157     | Weak association     |
| NF-CICIDS2018-v3 | L4_DST_PORT | 7271.51  | 0.00e+00  | 0.1907     | Weak association     |
| NF-ToN-IoT-v3    | L4_SRC_PORT | 23422.25 | 0.00e+00  | 0.3422     | Moderate association |
| NF-ToN-IoT-v3    | L4_DST_PORT | 61907.68 | 0.00e+00  | 0.5564     | Strong association   |
| NF-UNSW-NB15-v3  | L4_SRC_PORT | 1401.66  | 6.28e-287 | 0.0837     | Very weak/None       |
| NF-UNSW-NB15-v3  | L4_DST_PORT | 2132.21  | 0.00e+00  | 0.1033     | Weak association     |

## Highly Specific Ports (>80% associated with one label)

### NF-BoT-IoT-v3

**L4_SRC_PORT:**

| Port  | Service | Dominant Label | Specificity | Count  |
| ----- | ------- | -------------- | ----------- | ------ |
| 52071 | \-      | Reconnaissance | 99.7%       | 65,725 |
| 57044 | \-      | Reconnaissance | 99.7%       | 65,156 |
| 50428 | \-      | Reconnaissance | 99.7%       | 64,795 |
| 41607 | \-      | Reconnaissance | 99.7%       | 65,760 |
| 57184 | \-      | Reconnaissance | 99.7%       | 61,790 |
| 59460 | \-      | Reconnaissance | 99.6%       | 64,379 |
| 40081 | \-      | Reconnaissance | 99.6%       | 59,587 |
| 56304 | \-      | Reconnaissance | 99.6%       | 58,447 |
| 54114 | \-      | Reconnaissance | 99.6%       | 60,572 |
| 42640 | \-      | Reconnaissance | 99.6%       | 60,642 |
| 65233 | \-      | Reconnaissance | 99.6%       | 51,023 |
| 49731 | \-      | Reconnaissance | 99.6%       | 56,214 |
| 47422 | \-      | Reconnaissance | 99.6%       | 60,865 |
| 47095 | \-      | Reconnaissance | 99.6%       | 60,938 |
| 40850 | \-      | Reconnaissance | 99.6%       | 55,092 |

**L4_DST_PORT:**

| Port  | Service    | Dominant Label | Specificity | Count  |
| ----- | ---------- | -------------- | ----------- | ------ |
| 1883  | \-         | Reconnaissance | 100.0%      | 24,299 |
| 1880  | \-         | Reconnaissance | 100.0%      | 7,812  |
| 5432  | PostgreSQL | Reconnaissance | 99.9%       | 4,790  |
| 49155 | \-         | Reconnaissance | 99.9%       | 1,485  |
| 5900  | VNC        | Reconnaissance | 99.8%       | 578    |
| 6667  | \-         | Reconnaissance | 99.8%       | 553    |
| 49154 | \-         | Reconnaissance | 99.8%       | 1,475  |
| 995   | POP3S      | Reconnaissance | 99.8%       | 1,360  |
| 993   | IMAPS      | Reconnaissance | 99.8%       | 1,358  |
| 25    | SMTP       | Reconnaissance | 99.7%       | 1,387  |
| 49156 | \-         | Reconnaissance | 99.7%       | 1,484  |
| 49152 | \-         | Reconnaissance | 99.6%       | 1,574  |
| 49157 | \-         | Reconnaissance | 99.6%       | 1,478  |
| 49153 | \-         | Reconnaissance | 99.6%       | 1,565  |
| 8009  | \-         | Reconnaissance | 99.5%       | 874    |

### NF-CICIDS2018-v3

**L4_SRC_PORT:**

| Port  | Service | Dominant Label | Specificity | Count   |
| ----- | ------- | -------------- | ----------- | ------- |
| 138   | \-      | Benign         | 100.0%      | 60,764  |
| 546   | \-      | Benign         | 100.0%      | 38,125  |
| 445   | SMB     | Benign         | 100.0%      | 26,831  |
| 43411 | \-      | Benign         | 100.0%      | 11,004  |
| 46859 | \-      | Benign         | 100.0%      | 2,678   |
| 3389  | RDP     | Benign         | 100.0%      | 706,869 |
| 443   | HTTPS   | Benign         | 100.0%      | 98,922  |
| 80    | HTTP    | Benign         | 100.0%      | 23,577  |
| 137   | \-      | Benign         | 100.0%      | 14,915  |
| 6712  | \-      | Benign         | 99.9%       | 2,953   |
| 6666  | \-      | Benign         | 99.9%       | 9,284   |
| 0     | \-      | Benign         | 99.7%       | 67,358  |
| 42023 | \-      | Benign         | 99.7%       | 7,603   |
| 65535 | \-      | Benign         | 99.7%       | 3,226   |
| 54193 | \-      | Benign         | 99.4%       | 23,271  |

**L4_DST_PORT:**

| Port  | Service | Dominant Label | Specificity | Count   |
| ----- | ------- | -------------- | ----------- | ------- |
| 138   | \-      | Benign         | 100.0%      | 60,868  |
| 547   | \-      | Benign         | 100.0%      | 38,123  |
| 6553  | \-      | Benign         | 100.0%      | 2,643   |
| 2181  | \-      | Benign         | 100.0%      | 2,339   |
| 50010 | \-      | Benign         | 100.0%      | 2,306   |
| 6188  | \-      | Benign         | 100.0%      | 2,273   |
| 30303 | \-      | Benign         | 100.0%      | 2,213   |
| 33434 | \-      | Benign         | 100.0%      | 1,929   |
| 3397  | \-      | Benign         | 100.0%      | 1,076   |
| 7112  | \-      | Benign         | 100.0%      | 950     |
| 47808 | \-      | Benign         | 100.0%      | 877     |
| 49672 | \-      | Benign         | 100.0%      | 785     |
| 11211 | \-      | Benign         | 100.0%      | 3,606   |
| 5355  | \-      | Benign         | 100.0%      | 102,580 |
| 3128  | \-      | Benign         | 99.9%       | 56,158  |

### NF-ToN-IoT-v3

**L4_SRC_PORT:**

| Port  | Service  | Dominant Label | Specificity | Count     |
| ----- | -------- | -------------- | ----------- | --------- |
| 8080  | HTTP-Alt | Benign         | 100.0%      | 70,122    |
| 443   | HTTPS    | Benign         | 100.0%      | 3,378,364 |
| 53    | DNS      | Benign         | 100.0%      | 1,868,530 |
| 80    | HTTP     | Benign         | 100.0%      | 1,533,352 |
| 1880  | \-       | Benign         | 100.0%      | 142,452   |
| 0     | \-       | Benign         | 99.9%       | 241,831   |
| 5353  | \-       | Benign         | 99.9%       | 16,872    |
| 48433 | \-       | Benign         | 99.4%       | 8,989     |
| 44431 | \-       | Benign         | 99.3%       | 9,437     |
| 42103 | \-       | Benign         | 99.2%       | 9,163     |
| 57121 | \-       | Benign         | 99.2%       | 9,655     |
| 35447 | \-       | Benign         | 99.2%       | 9,454     |
| 50519 | \-       | Benign         | 99.2%       | 9,600     |
| 45189 | \-       | Benign         | 99.1%       | 8,992     |
| 55851 | \-       | Benign         | 99.0%       | 8,914     |

**L4_DST_PORT:**

| Port  | Service | Dominant Label | Specificity | Count   |
| ----- | ------- | -------------- | ----------- | ------- |
| 51642 | \-      | Benign         | 100.0%      | 883,791 |
| 60899 | \-      | Benign         | 100.0%      | 218,187 |
| 52970 | \-      | Benign         | 100.0%      | 377,506 |
| 57856 | \-      | Benign         | 100.0%      | 252,636 |
| 64391 | \-      | Benign         | 100.0%      | 37,228  |
| 15600 | \-      | Benign         | 100.0%      | 40,253  |
| 54674 | \-      | Benign         | 100.0%      | 45,070  |
| 49338 | \-      | Benign         | 100.0%      | 36,796  |
| 9197  | \-      | Benign         | 100.0%      | 40,699  |
| 41952 | \-      | Benign         | 100.0%      | 26,165  |
| 49255 | \-      | Benign         | 100.0%      | 17,013  |
| 52213 | \-      | Benign         | 100.0%      | 16,247  |
| 7678  | \-      | Benign         | 100.0%      | 9,083   |
| 50575 | \-      | Benign         | 100.0%      | 19,195  |
| 53768 | \-      | Benign         | 100.0%      | 14,134  |

### NF-UNSW-NB15-v3

**L4_SRC_PORT:**

| Port  | Service | Dominant Label | Specificity | Count |
| ----- | ------- | -------------- | ----------- | ----- |
| 21    | FTP     | Benign         | 100.0%      | 918   |
| 25    | SMTP    | Benign         | 100.0%      | 156   |
| 143   | IMAP    | Benign         | 100.0%      | 118   |
| 1884  | \-      | Benign         | 100.0%      | 96    |
| 5190  | \-      | Benign         | 99.4%       | 179   |
| 2041  | \-      | Benign         | 99.1%       | 109   |
| 1585  | \-      | Benign         | 99.0%       | 104   |
| 1446  | \-      | Benign         | 99.0%       | 104   |
| 1660  | \-      | Benign         | 99.0%       | 103   |
| 1669  | \-      | Benign         | 99.0%       | 101   |
| 44620 | \-      | Benign         | 99.0%       | 97    |
| 1237  | \-      | Benign         | 98.9%       | 95    |
| 1665  | \-      | Benign         | 98.9%       | 95    |
| 80    | HTTP    | Benign         | 98.6%       | 515   |
| 6881  | \-      | Benign         | 98.4%       | 250   |

**L4_DST_PORT:**

| Port  | Service | Dominant Label | Specificity | Count   |
| ----- | ------- | -------------- | ----------- | ------- |
| 6881  | \-      | Benign         | 100.0%      | 115,744 |
| 24160 | \-      | Benign         | 100.0%      | 468     |
| 25885 | \-      | Benign         | 100.0%      | 403     |
| 3354  | \-      | Benign         | 100.0%      | 392     |
| 52561 | \-      | Benign         | 100.0%      | 388     |
| 61097 | \-      | Benign         | 100.0%      | 378     |
| 7395  | \-      | Benign         | 100.0%      | 344     |
| 19414 | \-      | Benign         | 100.0%      | 315     |
| 17511 | \-      | Benign         | 100.0%      | 302     |
| 63656 | \-      | Benign         | 100.0%      | 300     |
| 30639 | \-      | Benign         | 100.0%      | 297     |
| 5658  | \-      | Benign         | 100.0%      | 297     |
| 38742 | \-      | Benign         | 100.0%      | 297     |
| 19012 | \-      | Benign         | 100.0%      | 296     |
| 32912 | \-      | Benign         | 100.0%      | 294     |

## Key Findings

### Port-Attack Associations

- **SSH (22)**: Often associated with brute-force attacks (SSH-Bruteforce, password attacks)
- **HTTP/HTTPS (80, 443, 8080)**: Associated with web attacks (XSS, SQL injection, DDoS)
- **FTP (20, 21)**: Associated with FTP brute-force attacks
- **DNS (53)**: Can indicate reconnaissance or DNS-based attacks
- **High ports (>1024)**: Often used in DoS/DDoS attacks, C2 communications
- **Dynamic ports (>49152)**: May indicate scanning, C2, or lateral movement

## Interpretation Guide

- **Cramer's V**: Measures association strength (0-1)
  - 0.0-0.1: Very weak or no association
  - 0.1-0.3: Weak association
  - 0.3-0.5: Moderate association
  - 0.5+: Strong association
- **Chi p-value**: \<0.05 indicates statistically significant association
- **Specificity**: % of traffic on a port belonging to one label
