"""task #15 score — ko-output-guard 룰 + GPU 예측 결합 → 경쟁 표.

sqlguard venv(pydantic)에서 ko-output-guard Guard().check(결정론 룰) 실행 → GPU 예측
(output_preds_gpu.json)과 합쳐 per-dataset recall/FPR/F1 + **의료 FPR**.

스토리: 경쟁군(kor_unsmile/Detoxify/Llama-Guard)은 한국어 hate/tox는 잡아도 식약처 benign
의료문을 과탐(부분문자열·일반독성). ko-output-guard는 룰+통합분류기로 의료 FPR을 낮게 유지.
"""
from __future__ import annotations

import json
import sys

from _paths import OUTPUT_SRC, eval_path

sys.path.insert(0, str(OUTPUT_SRC))
from ko_output_guard import Guard, Verdict

PREDS = eval_path("output_preds_gpu.json")
OUT = eval_path("bench_output_report.json")
G = Guard()
THR = 0.5


def metrics(flags, labels):
    tp = sum(1 for f, y in zip(flags, labels) if f and y == 1)
    fp = sum(1 for f, y in zip(flags, labels) if f and y == 0)
    fn = sum(1 for f, y in zip(flags, labels) if not f and y == 1)
    tn = sum(1 for f, y in zip(flags, labels) if not f and y == 0)
    rec = tp / (tp + fn) * 100 if tp + fn else None
    fpr = fp / (fp + tn) * 100 if fp + tn else None
    prec = tp / (tp + fp) * 100 if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if rec and prec + rec else (0.0 if rec is not None else None)
    return {"recall": round(rec, 1) if rec is not None else None,
            "fpr": round(fpr, 1) if fpr is not None else None,
            "f1": round(f1, 1) if f1 is not None else None}


def main():
    preds = json.load(open(PREDS))
    report = {}
    SYS = ["ko_output_full", "ko_rules", "kor_unsmile", "detoxify", "llama_guard"]
    for ds, d in preds.items():
        texts, labels = d["texts"], d["labels"]
        rule_flags = [G.check(t).verdict is not Verdict.SAFE for t in texts]
        uni = d["ko_unified"]
        full_flags = [r or (u > THR) for r, u in zip(rule_flags, uni)]
        cols = {"ko_output_full": full_flags, "ko_rules": rule_flags}
        for key in ("kor_unsmile", "detoxify", "llama_guard"):
            if key in d:
                cols[key] = [p > THR for p in d[key]]
        report[ds] = {s: metrics(cols[s], labels) for s in cols}

    # 표 1 — 한국어 hate/tox 검출 (held-out)
    print("=== 한국어 hate/tox 검출 (recall% / FPR%) ===")
    print(f"{'dataset':16} | " + " | ".join(f"{s:>14}" for s in SYS))
    for ds in ["tox_kmhas", "tox_apeach", "aihub_ethics", "toxicity", "khaters"]:
        if ds not in report:
            continue
        cells = []
        for s in SYS:
            m = report[ds].get(s)
            cells.append(f"{m['recall']:5.1f}/{m['fpr']:4.1f}" if m and m['recall'] is not None else "   -  ")
        print(f"{ds:16} | " + " | ".join(f"{c:>14}" for c in cells))

    # 표 2 — 의료 도메인 FPR (핵심 차별)
    print("\n=== 의료 도메인 FPR (식약처 benign 의료문 과탐율, 낮을수록 좋음) ===")
    med = report.get("medical_benign", {})
    for s in SYS:
        m = med.get(s)
        if m and m["fpr"] is not None:
            print(f"  {s:16} 의료FPR = {m['fpr']:5.2f}%")
    json.dump(report, open(OUT, "w"), ensure_ascii=False, indent=2)
    print(f"\nsaved → {OUT}")


if __name__ == "__main__":
    main()
