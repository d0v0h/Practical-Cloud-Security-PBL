# Category 3: ServiceAccount 토큰 악용 탐지 (Kubernetes Audit Log)

탈취된 ServiceAccount 토큰으로 API 서버를 호출하는 행동을 Audit Log로 탐지한다.
정상 앱과 공격자의 계정이 같으므로, 요청 내용(verb, resource, subresource, namespace)으로 구분한다.

## 진행
1. 제공 시나리오(`category3/`)로 v1 규칙 작성
2. 추가 공격 시나리오 3개로 v1 검증 → 2개 미탐
3. v2 규칙 설계 (계정별 정상 행동 = 허용 목록)
4. v2 설계에 쓰지 않은 시나리오 4개로 v2 검증

## 탐지 규칙
**v1 (차단 목록)**
```text
(verb == list AND resource == secrets) OR (verb == create AND resource == pods/exec)
```

**v2 (허용 목록)**: 계정별 정상 행동은 `detector/profiles.json`

| 규칙 | 조건 | 위험도 |
|---|---|---|
| Rule 1 | 정상 행동 밖의 요청 | medium |
| Rule 2 | 정상 행동 밖 + 민감 리소스 (secrets, pods/exec, roles 등) | high |
| Rule 3 | 30초 안에 403이 3회 이상 | medium |

요청이 성공(2xx)하면 위험도 한 단계 상승 (low < medium < high < critical)

## 추가 시나리오
| 시나리오 | 구분 | 내용 | 용도 |
|---|---|---|---|
| a_get_secret | 공격 | Secret을 get으로 하나만 조회 | v1 검증 |
| a_cluster_recon | 공격 | 권한 확인 후 nodes, roles 등 정찰 | v1 검증 |
| a_overpriv_secret | 공격 | 권한 과다 계정으로 Secret 조회 성공 | v1 검증 |
| n_burst | 정상 | 허용된 조회를 빠르게 반복 | v2 검증 |
| n_operator_exec | 정상 | 운영자 계정의 exec | v2 검증 |
| n_misconfig_403 | 정상 | 권한 누락으로 403 반복 | v2 검증 |
| a_slow_recon | 공격 | 허용된 조회만 천천히 반복 | v2 검증 |

## 결과
| 시나리오 | v1 | v2 |
|---|---|---|
| a_get_secret | 미탐 | 탐지 |
| a_cluster_recon | 미탐 | 탐지 |
| a_overpriv_secret | 탐지 | 탐지 (critical) |
| n_burst | 통과 | 통과 |
| n_operator_exec | 통과 | 통과 |
| n_misconfig_403 | 통과 | 오탐 |
| a_slow_recon | 미탐 | 미탐 |

- 오탐: Rule 3가 403의 원인(설정 실수 vs 권한 시험)을 구분하지 못함
- 미탐: 정상 앱과 같은 요청만 사용해 요청 내용으로 구분 불가
- 상세: `results/summary.md`, `results/v1_vs_v2.md`

## 한계
- v2는 v1 검증용 공격 3개를 참고해 설계했으므로 그 결과는 v2에 유리함
- Audit Log로 Pod 침투, 토큰 파일 읽기는 확인 불가
- 정상 행동 목록을 수동으로 관리해야 함

## 실행 (저장소 루트에서)
```bash
chmod +x cat3/collect.sh cat3/scenarios/*.sh
./cat3/collect.sh 3 35                 # 시나리오 실행, 라벨 기록, 로그 추출 (약 30분)
python3 cat3/detector/detect.py        # v2 탐지
python3 cat3/detector/evaluate.py      # v2 평가
python3 cat3/detector/evaluate_v1.py   # v1 vs v2 비교
```

## 구성
| 경로 | 내용 |
|---|---|
| `scenarios/` | 추가 시나리오 |
| `collect.sh` | 수집 스크립트 |
| `detector/` | 탐지 규칙, 평가 코드 |
| `data/` | 수집 로그, 실행 라벨 |
| `results/` | 탐지·평가 결과 |

## AI 사용
추가 시나리오 스크립트와 탐지·평가 코드는 Claude의 도움을 받아 작성했다. 실행, 결과 확인, 분석은 직접 수행했다.
