"""탐지 결과를 실행 라벨과 비교해 실행(run) 단위로 평가한다.

실행 하나에 알림이 하나라도 있으면 '공격으로 탐지'로 본다.
  TP: 공격 실행을 탐지   FN: 공격 실행을 놓침
  FP: 정상 실행을 탐지   TN: 정상 실행을 통과

사용법: python3 evaluate.py
출력:   results/run_results.csv, results/summary.md
"""
import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GRACE = timedelta(seconds=2)   # 스크립트 종료와 로그 기록 사이의 여유


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def metrics(rows):
    c = defaultdict(int)
    for r in rows:
        c[r["outcome"]] += 1
    tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, precision=p, recall=r, f1=f1, fpr=fpr)


def main():
    labels = list(csv.DictReader(open(ROOT / "data/labels.csv", encoding="utf-8")))
    alerts = list(csv.DictReader(open(ROOT / "results/alerts.csv", encoding="utf-8")))
    sys.path.insert(0, str(HERE))
    from detect import load_events
    events = load_events(ROOT / "data/raw/audit_pbl.jsonl")

    rows = []
    for lb in labels:
        start, end = ts(lb["start"]), ts(lb["end"]) + GRACE
        run_events = [e for e in events if start <= e["ts"] <= end]
        run_alerts = [a for a in alerts if start <= ts(a["ts"]) <= end]
        detected = bool(run_alerts)
        attack = lb["label"] == "attack"
        outcome = {(True, True): "TP", (True, False): "FN",
                   (False, True): "FP", (False, False): "TN"}[(attack, detected)]
        ttd = ""
        if detected and run_events:
            first = min(ts(a["ts"]) for a in run_alerts)
            ttd = f"{(first - run_events[0]['ts']).total_seconds():.2f}"
        rows.append({
            "run_id": lb["run_id"], "scenario": lb["scenario"], "label": lb["label"],
            "split": lb["split"], "events": len(run_events),
            "codes": " ".join(sorted({str(e["code"]) for e in run_events})),
            "alerts": len(run_alerts),
            "rules": " ".join(sorted({a["rule"] for a in run_alerts})),
            "max_severity": max((a["severity"] for a in run_alerts),
                                key=["low", "medium", "high", "critical"].index, default=""),
            "detected": detected, "outcome": outcome, "time_to_detect_s": ttd,
        })

    out = ROOT / "results/run_results.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # 시나리오별 요약
    by_sc = defaultdict(list)
    for r in rows:
        by_sc[r["scenario"]].append(r)
    lines = ["# Category 3 탐지 평가 결과", "",
             "## 전체 지표 (실행 단위)", "",
             "| 데이터 | TP | FP | FN | TN | Precision | Recall | F1 | FPR |",
             "|---|---|---|---|---|---|---|---|---|"]
    for name, subset in [("dev", [r for r in rows if r["split"] == "dev"]),
                         ("test", [r for r in rows if r["split"] == "test"]),
                         ("all", rows)]:
        m = metrics(subset)
        lines.append(f"| {name} | {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} | "
                     f"{m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | {m['fpr']:.2f} |")
    lines += ["", "## 시나리오별 결과", "",
              "| 시나리오 | 라벨 | split | 실행 | 탐지 | 결과 | 응답 코드 | 발생 규칙 | 최고 위험도 |",
              "|---|---|---|---|---|---|---|---|---|"]
    for sc, rs in by_sc.items():
        det = sum(r["detected"] for r in rs)
        outcomes = " ".join(sorted({r["outcome"] for r in rs}))
        rules = " ".join(sorted({x for r in rs for x in r["rules"].split()}))
        codes = " ".join(sorted({x for r in rs for x in r["codes"].split()}))
        sev = max((r["max_severity"] for r in rs if r["max_severity"]),
                  key=["low", "medium", "high", "critical"].index, default="-")
        lines.append(f"| {sc} | {rs[0]['label']} | {rs[0]['split']} | {len(rs)} | {det} | "
                     f"{outcomes} | {codes or '-'} | {rules or '-'} | {sev} |")
    (ROOT / "results/summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n상세: {out}")


if __name__ == "__main__":
    main()
