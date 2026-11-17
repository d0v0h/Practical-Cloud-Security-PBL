#!/usr/bin/env bash
# [정상] 운영자가 장애 대응으로 backend Pod에서 명령 실행 (exec 성공, 정상 업무)
source "$(dirname "$0")/common.sh"
use_identity "${OPS_SA}"
POD="$("${K[@]}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"
"${K[@]}" exec "${POD}" -- date
