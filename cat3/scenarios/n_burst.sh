#!/usr/bin/env bash
# [정상] 앱이 바쁜 시간에 허용된 조회를 빠르게 반복 (요청 수가 많아도 정상)
source "$(dirname "$0")/common.sh"
use_identity "${APP_SA}"
for i in $(seq 1 8); do
  "${K[@]}" get pods >/dev/null
  "${K[@]}" get services >/dev/null
  "${K[@]}" get configmaps >/dev/null
done
