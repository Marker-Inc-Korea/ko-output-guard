"""ko-guard suite vs LLM Guard (protectai/llm-guard) — 에이전틱 보안 harness 한국어 비교.

LLM Guard = 에이전틱 AI 시대의 OSS 보안 툴킷(input/output 다중 스캐너). 영어 우선이라
한국어에서 ko-guard 대비 어떤지 동일 셋·동일 채점으로 본다.

  · PromptInjection 스캐너 vs ko-prompt-guard : prompt_eval_sets(평문+난독)
  · Toxicity 스캐너 vs ko-output-guard : 한국어 toxicity 셋 + 의료 benign FPR

harness_venv(llm_guard 설치)에서 실행. ko-guard 측 수치는 기존 리포트와 비교.
"""
from __future__ import annotations

import glob
import json

SETS = "/data1/mk04/eval_external/prompt_eval_sets.json"
EVAL = "/data1/mk04/projects/ko-pii/experiments/ko-output-guard/eval/external"
QTAOA = "/data1/mk04/medi/agentic_v3/data/qtaoa_combined.jsonl"
OUT = "/data1/mk04/eval_external/llmguard_report.json"


def metrics(flags, labels):
    tp = sum(1 for f, y in zip(flags, labels) if f and y == 1)
    fp = sum(1 for f, y in zip(flags, labels) if f and y == 0)
    fn = sum(1 for f, y in zip(flags, labels) if not f and y == 1)
    tn = sum(1 for f, y in zip(flags, labels) if not f and y == 0)
    rec = tp / (tp + fn) * 100 if tp + fn else None
    fpr = fp / (fp + tn) * 100 if fp + tn else None
    return {"recall": round(rec, 1) if rec is not None else None,
            "fpr": round(fpr, 1) if fpr is not None else None}


def load_med(n=200):
    out = []
    for line in open(QTAOA):
        if not line.strip():
            continue
        r = json.loads(line)
        a = [m for m in r.get("messages", []) if m.get("role") == "assistant" and m.get("content")]
        if a and len(a[-1]["content"].strip()) >= 40:
            out.append(a[-1]["content"].strip()[:600])
        if len(out) >= n:
            break
    return out


def main():
    report = {"harness": "protectai/llm-guard"}

    # --- 1) PromptInjection ---
    from llm_guard.input_scanners import PromptInjection
    try:
        from llm_guard.input_scanners.prompt_injection import MatchType
        pi = PromptInjection(threshold=0.5, match_type=MatchType.FULL)
    except Exception:
        pi = PromptInjection(threshold=0.5)

    def pi_flag(text):
        try:
            _, is_valid, _ = pi.scan(text)
            return not is_valid
        except Exception:
            return False

    sets = json.load(open(SETS))
    report["prompt_injection"] = {}
    print("=== LLM Guard PromptInjection (한국어 인젝션) ===")
    for variant in ["plain_ko", "obf_jamo", "obf_zerowidth", "obf_fullwidth", "deepset_ko"]:
        rows = sets[variant]
        flags = [pi_flag(t) for t, _ in rows]
        labels = [y for _, y in rows]
        m = metrics(flags, labels)
        report["prompt_injection"][variant] = m
        print(f"  {variant:14} recall={m['recall']}  fpr={m['fpr']}")

    # --- 2) Toxicity ---
    from llm_guard.output_scanners import Toxicity
    tox = Toxicity(threshold=0.5)

    def tox_flag(text):
        try:
            _, is_valid, _ = tox.scan("", text)
            return not is_valid
        except Exception:
            return False

    report["toxicity"] = {}
    print("\n=== LLM Guard Toxicity (한국어 toxicity/hate) ===")
    for name in ["tox_kmhas", "tox_apeach", "aihub_ethics"]:
        rows = [json.loads(l) for l in open(f"{EVAL}/{name}.jsonl") if l.strip()]
        texts = [r["text"] for r in rows]
        labels = [int(r["label"]) for r in rows]
        flags = [tox_flag(t) for t in texts]
        m = metrics(flags, labels)
        report["toxicity"][name] = m
        print(f"  {name:14} recall={m['recall']}  fpr={m['fpr']}")
    # 의료 FPR
    med = load_med()
    medflags = [tox_flag(t) for t in med]
    mfpr = round(sum(medflags) / len(med) * 100, 2)
    report["toxicity"]["medical_fpr"] = mfpr
    print(f"  medical_FPR    = {mfpr}%")

    json.dump(report, open(OUT, "w"), ensure_ascii=False, indent=2)
    print(f"\nsaved → {OUT}")


if __name__ == "__main__":
    main()
