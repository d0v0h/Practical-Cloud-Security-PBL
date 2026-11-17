# Category 3 탐지 평가 결과

## 전체 지표 (실행 단위)

| 데이터 | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| dev | 9 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 | 0.00 |
| test | 9 | 3 | 3 | 6 | 0.75 | 0.75 | 0.75 | 0.33 |
| all | 18 | 3 | 3 | 9 | 0.86 | 0.86 | 0.86 | 0.25 |

## 시나리오별 결과

| 시나리오 | 라벨 | split | 실행 | 탐지 | 결과 | 응답 코드 | 발생 규칙 | 최고 위험도 |
|---|---|---|---|---|---|---|---|---|
| normal | normal | dev | 3 | 0 | TN | 200 | - | - |
| abnormal_1 | attack | dev | 3 | 3 | TP | 403 | R2_SENSITIVE | high |
| abnormal_2 | attack | dev | 3 | 3 | TP | 200 403 | R2_SENSITIVE | high |
| abnormal_3 | attack | dev | 3 | 3 | TP | 200 403 | R2_SENSITIVE R3_DENIAL_BURST | high |
| n_burst | normal | test | 3 | 0 | TN | 200 | - | - |
| n_operator_exec | normal | test | 3 | 0 | TN | 101 200 | - | - |
| n_misconfig_403 | normal | test | 3 | 3 | FP | 200 403 | R3_DENIAL_BURST | medium |
| a_get_secret | attack | test | 3 | 3 | TP | 403 | R2_SENSITIVE | high |
| a_cluster_recon | attack | test | 3 | 3 | TP | 201 403 | R1_OUT_OF_PROFILE R2_SENSITIVE R3_DENIAL_BURST | high |
| a_overpriv_secret | attack | test | 3 | 3 | TP | 200 | R2_SENSITIVE | critical |
| a_slow_recon | attack | test | 3 | 0 | FN | 200 | - | - |
