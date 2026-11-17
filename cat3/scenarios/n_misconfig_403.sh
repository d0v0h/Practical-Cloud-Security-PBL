#!/usr/bin/env bash
# [정상] 앱이 서비스 탐색용 endpoints를 조회하지만 RBAC에 권한이 빠진 설정 실수
#        재시도 때문에 403이 반복된다 (공격 아님 → 오탐 유도)
source "$(dirname "$0")/common.sh"
use_identity "${APP_SA}"
"${K[@]}" get pods >/dev/null
for i in $(seq 1 4); do
  try "${K[@]}" get endpoints backend
  sleep 1
done
