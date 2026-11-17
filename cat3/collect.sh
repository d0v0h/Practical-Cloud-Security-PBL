#!/usr/bin/env bash
# 시나리오를 차례로 실행하며 라벨(시작·종료 시각)을 기록하고, 끝나면 Audit Log를 추출한다.
# 사용법: ./cat3/collect.sh [반복 횟수=3] [실행 간격(초)=35]
set -euo pipefail

REPEAT="${1:-3}"
GAP="${2:-35}"            # 탐지 구간(30초)보다 길게 두어 실행끼리 섞이지 않게 함
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
DATA="${HERE}/data"
LABELS="${DATA}/labels.csv"
mkdir -p "${DATA}/raw" "${DATA}/stdout"

# scenario | 실행 파일 | label | split(dev: 규칙 설계에 사용, test: 평가 전용)
SCENARIOS=(
  "normal|${ROOT}/category3/normal.sh|normal|dev"
  "abnormal_1|${ROOT}/category3/abnormal_1.sh|attack|dev"
  "abnormal_2|${ROOT}/category3/abnormal_2.sh|attack|dev"
  "abnormal_3|${ROOT}/category3/abnormal_3.sh|attack|dev"
  "n_burst|${HERE}/scenarios/n_burst.sh|normal|test"
  "n_operator_exec|${HERE}/scenarios/n_operator_exec.sh|normal|test"
  "n_misconfig_403|${HERE}/scenarios/n_misconfig_403.sh|normal|test"
  "a_get_secret|${HERE}/scenarios/a_get_secret.sh|attack|test"
  "a_cluster_recon|${HERE}/scenarios/a_cluster_recon.sh|attack|test"
  "a_overpriv_secret|${HERE}/scenarios/a_overpriv_secret.sh|attack|test"
  "a_slow_recon|${HERE}/scenarios/a_slow_recon.sh|attack|test"
)

now() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }

echo "[setup] 실습 계정과 권한을 준비합니다."
source "${HERE}/scenarios/common.sh"
setup_identities
sleep "${GAP}"

echo "run_id,scenario,label,split,start,end,exit_code" > "${LABELS}"
for entry in "${SCENARIOS[@]}"; do
  IFS='|' read -r name script label split <<<"${entry}"
  for i in $(seq 1 "${REPEAT}"); do
    run_id="${name}_$(printf '%02d' "${i}")"
    echo "[run] ${run_id} (${label})"
    start="$(now)"
    set +e
    bash "${script}" >"${DATA}/stdout/${run_id}.txt" 2>&1
    rc=$?
    set -e
    end="$(now)"
    echo "${run_id},${name},${label},${split},${start},${end},${rc}" >> "${LABELS}"
    [[ ${rc} -ne 0 ]] && echo "  ! exit=${rc}, ${DATA}/stdout/${run_id}.txt 확인"
    sleep "${GAP}"
  done
done

echo "[export] pbl 계정의 Audit Log만 추출합니다 (sudo 필요)."
sudo python3 "${HERE}/detector/extract.py" \
  "${ROOT}"/.generated/audit-logs/audit*.log > "${DATA}/raw/audit_pbl.jsonl"
wc -l "${LABELS}" "${DATA}/raw/audit_pbl.jsonl"
echo "완료. 다음: python3 ${HERE}/detector/detect.py && python3 ${HERE}/detector/evaluate.py"
