"""Audit Log에서 실습 계정(pbl-*)의 완료 이벤트만 추출해 JSON Lines로 출력한다.
사용법: sudo python3 extract.py audit.log [audit-*.log ...] > audit_pbl.jsonl
"""
import json
import sys

PREFIX = "system:serviceaccount:pbl-security:pbl-"

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("stage") != "ResponseComplete":
                continue  # 요청 시작(RequestReceived) 기록은 중복이므로 제외
            if ev.get("user", {}).get("username", "").startswith(PREFIX):
                print(json.dumps(ev, ensure_ascii=False))
