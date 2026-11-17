# v1(list secrets, create pods/exec) vs v2(R1~R3)

## test 데이터 지표

| 규칙 | TP | FP | FN | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| v1 | 3 | 0 | 9 | 9 | 1.00 | 0.25 |
| v2 | 9 | 3 | 3 | 6 | 0.75 | 0.75 |

## 시나리오별

| 시나리오 | 라벨 | split | v1 | v2 |
|---|---|---|---|---|
| normal | normal | dev | TN | TN |
| abnormal_1 | attack | dev | TP | TP |
| abnormal_2 | attack | dev | TP | TP |
| abnormal_3 | attack | dev | TP | TP |
| n_burst | normal | test | TN | TN |
| n_operator_exec | normal | test | TN | TN |
| n_misconfig_403 | normal | test | TN | FP |
| a_get_secret | attack | test | FN | TP |
| a_cluster_recon | attack | test | FN | TP |
| a_overpriv_secret | attack | test | TP | TP |
| a_slow_recon | attack | test | FN | FN |
