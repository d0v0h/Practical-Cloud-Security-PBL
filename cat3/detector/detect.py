"""Kubernetes Audit Log 기반 ServiceAccount 악용 탐지기.

규칙
  R1 OUT_OF_PROFILE  계정의 정상 행동 목록(profiles.json) 밖의 요청
  R2 SENSITIVE       R1 중 Secret, exec 등 민감 리소스에 대한 요청
  R3 DENIAL_BURST    window_seconds 안에 403이 denial_threshold 회 이상

위험도: 요청이 성공(2xx/101)하면 한 단계 올린다. 403보다 성공한 공격이 더 위험하기 때문.

사용법: python3 detect.py [audit_pbl.jsonl] [alerts.csv]
"""
import csv
import json
import sys
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEVELS = ["low", "medium", "high", "critical"]


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def bump(level, n=1):
    return LEVELS[min(LEVELS.index(level) + n, len(LEVELS) - 1)]


def load_events(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if ev.get("stage") != "ResponseComplete":
                continue
            ref = ev.get("objectRef") or {}
            resource = ref.get("resource", "-")
            if ref.get("subresource"):
                resource += "/" + ref["subresource"]
            events.append({
                "ts": parse_ts(ev["requestReceivedTimestamp"]),
                "user": ev.get("user", {}).get("username", ""),
                "verb": ev.get("verb", ""),
                "resource": resource,
                "namespace": ref.get("namespace") or "(cluster)",
                "code": (ev.get("responseStatus") or {}).get("code", 0),
                "user_agent": ev.get("userAgent", ""),
                "uri": ev.get("requestURI", ""),
            })
    events.sort(key=lambda e: e["ts"])
    return events


def detect(events, cfg):
    accounts = cfg["accounts"]
    sensitive = set(cfg["sensitive_resources"])
    window = cfg["window_seconds"]
    threshold = cfg["denial_threshold"]
    denials = defaultdict(deque)        # 계정별 최근 403 시각
    last_burst = {}                     # 계정별 마지막 R3 알림 시각 (중복 알림 방지)
    alerts = []

    for ev in events:
        prof = accounts.get(ev["user"])
        if prof is None:
            continue                    # 모니터링 대상이 아닌 계정
        success = ev["code"] < 400
        in_profile = (
            ev["verb"] in prof["allowed"].get(ev["resource"], [])
            and ev["namespace"] in prof["namespaces"]
        )

        def add(rule, level, reason):
            alerts.append({**ev, "ts": ev["ts"].isoformat(), "rule": rule,
                           "severity": bump(level) if success else level,
                           "reason": reason})

        if not in_profile:
            if ev["resource"] in sensitive:
                add("R2_SENSITIVE", "high",
                    f"정상 목록 밖의 민감 리소스 {ev['verb']} {ev['resource']}")
            else:
                add("R1_OUT_OF_PROFILE", "medium",
                    f"정상 목록 밖의 요청 {ev['verb']} {ev['resource']} ns={ev['namespace']}")

        if ev["code"] == 403:
            q = denials[ev["user"]]
            q.append(ev["ts"])
            while (ev["ts"] - q[0]).total_seconds() > window:
                q.popleft()
            prev = last_burst.get(ev["user"])
            if len(q) >= threshold and (prev is None or (ev["ts"] - prev).total_seconds() > window):
                last_burst[ev["user"]] = ev["ts"]
                add("R3_DENIAL_BURST", "medium",
                    f"{window}초 안에 403 {len(q)}회 (권한 시험 의심)")
    return alerts


def main():
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "data/raw/audit_pbl.jsonl"
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE.parent / "results/alerts.csv"
    cfg = json.loads((HERE / "profiles.json").read_text(encoding="utf-8"))
    events = load_events(src)
    alerts = detect(events, cfg)

    out.parent.mkdir(parents=True, exist_ok=True)
    cols = ["ts", "severity", "rule", "user", "verb", "resource", "namespace",
            "code", "user_agent", "reason"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(alerts)

    print(f"events={len(events)} alerts={len(alerts)} -> {out}")
    for a in alerts:
        print(f"{a['ts'][11:23]} {a['severity']:8} {a['rule']:18} "
              f"{a['user'].split(':')[-1]:24} {a['verb']:6} {a['resource']:24} {a['code']}")


if __name__ == "__main__":
    main()
