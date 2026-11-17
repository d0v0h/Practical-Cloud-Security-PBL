"""v1 규칙(list secrets, create pods/exec 요청이면 탐지)과 v2 규칙(R1~R3)을 같은 데이터로 비교한다.

사용법: python3 evaluate_v1.py   (detect.py, evaluate.py 실행 후)
출력:   results/v1_vs_v2.md
"""
import csv
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GRACE = timedelta(seconds=2)
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from detect import load_events  # noqa: E402


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def v1_hit(e):
    return (e["verb"] == "list" and e["resource"] == "secrets") or \
           (e["verb"] == "create" and e["resource"] == "pods/exec")


def outcome(attack, detected):
    return {(True, True): "TP", (True, False): "FN",
            (False, True): "FP", (False, False): "TN"}[(attack, detected)]


def main():
    labels = list(csv.DictReader(open(ROOT / "data/labels.csv", encoding="utf-8")))
    v2 = {r["run_id"]: r for r in csv.DictReader(open(ROOT / "results/run_results.csv", encoding="utf-8"))}
    events = load_events(ROOT / "data/raw/audit_pbl.jsonl")

    per_sc, counts = {}, {"v1": {}, "v2": {}}
    for lb in labels:
        start, end = ts(lb["start"]), ts(lb["end"]) + GRACE
        run_ev = [e for e in events if start <= e["ts"] <= end]
        attack = lb["label"] == "attack"
        o1 = outcome(attack, any(v1_hit(e) for e in run_ev))
        o2 = v2[lb["run_id"]]["outcome"]
        if lb["split"] == "test":
            for name, o in (("v1", o1), ("v2", o2)):
                counts[name][o] = counts[name].get(o, 0) + 1
        per_sc.setdefault(lb["scenario"], (lb["label"], lb["split"], set(), set()))
        per_sc[lb["scenario"]][2].add(o1)
        per_sc[lb["scenario"]][3].add(o2)

    lines = ["# v1(list secrets, create pods/exec) vs v2(R1~R3)", "",
             "## test 데이터 지표", "",
             "| 규칙 | TP | FP | FN | TN | Precision | Recall |", "|---|---|---|---|---|---|---|"]
    for name in ("v1", "v2"):
        c = counts[name]
        tp, fp, fn, tn = (c.get(k, 0) for k in ("TP", "FP", "FN", "TN"))
        p = tp / (tp + fp) if tp + fp else 0
        r = tp / (tp + fn) if tp + fn else 0
        lines.append(f"| {name} | {tp} | {fp} | {fn} | {tn} | {p:.2f} | {r:.2f} |")
    lines += ["", "## 시나리오별", "", "| 시나리오 | 라벨 | split | v1 | v2 |", "|---|---|---|---|---|"]
    for sc, (label, split, o1, o2) in per_sc.items():
        lines.append(f"| {sc} | {label} | {split} | {' '.join(sorted(o1))} | {' '.join(sorted(o2))} |")
    (ROOT / "results/v1_vs_v2.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
