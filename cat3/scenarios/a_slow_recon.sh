#!/usr/bin/env bash
# [공격] 허용된 리소스만 천천히 조회하는 정찰 (403도, 금지 리소스도 없음 → 미탐 예상)
source "$(dirname "$0")/common.sh"
use_identity "${APP_SA}"
for r in pods services configmaps; do
  "${K[@]}" get "${r}" -o yaml >/dev/null
  sleep 10
done
"${K[@]}" get configmaps -o name | while read -r cm; do
  "${K[@]}" get "${cm}" -o yaml >/dev/null
done
