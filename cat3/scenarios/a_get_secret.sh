#!/usr/bin/env bash
# [공격] 이름을 알고 있는 Secret 하나를 get으로 직접 조회 (list가 아닌 변형)
source "$(dirname "$0")/common.sh"
use_identity "${APP_SA}"
try "${K[@]}" get secret pbl-db-credentials
