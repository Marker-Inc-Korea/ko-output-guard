"""LLM Guard 의 Toxicity 엔진(unitary/toxic-bert, 영어)을 한국어 toxicity 셋에 직접 측정.

LLM Guard Toxicity 스캐너 = toxic-bert wrapper. 영어 학습이라 한국어에서 어떤지 본다.
ko-output-guard(95.6/83.2 recall)·kor_unsmile 과 동일 셋 비교용. ner_env(GPU).
"""
from __future__ import annotations

import json
import os

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from _paths import KO_PII_EVAL_ROOT, eval_path

EVAL = str(KO_PII_EVAL_ROOT)
QTAOA = os.environ.get("KO_GUARD_BENIGN_CORPUS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures/benign_ko_sample.jsonl"))
OUT = eval_path("toxbert_report.json")
DEV = "cuda" if torch.cuda.is_available() else "cpu"
THR = 0.5


@torch.no_grad()
def ptoxic(texts, bs=32):
    tok = AutoTokenizer.from_pretrained("unitary/toxic-bert", use_fast=True)
    net = AutoModelForSequenceClassification.from_pretrained("unitary/toxic-bert").eval().to(DEV)
    out = []
    for i in range(0, len(texts), bs):
        enc = tok(texts[i:i+bs], padding=True, truncation=True, max_length=256, return_tensors="pt").to(DEV)
        out.extend(torch.sigmoid(net(**enc).logits[:, 0]).cpu().tolist())  # label0 = toxic
    return out


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


def metrics(probs, labels):
    flags = [p > THR for p in probs]
    tp = sum(1 for f, y in zip(flags, labels) if f and y == 1)
    fp = sum(1 for f, y in zip(flags, labels) if f and y == 0)
    fn = sum(1 for f, y in zip(flags, labels) if not f and y == 1)
    tn = sum(1 for f, y in zip(flags, labels) if not f and y == 0)
    rec = tp / (tp + fn) * 100 if tp + fn else None
    fpr = fp / (fp + tn) * 100 if fp + tn else None
    return {"recall": round(rec, 1) if rec is not None else None,
            "fpr": round(fpr, 1) if fpr is not None else None}


def main():
    report = {"engine": "unitary/toxic-bert (LLM Guard Toxicity)"}
    print("=== LLM Guard Toxicity 엔진(toxic-bert, 영어) on 한국어 ===")
    for name in ["tox_kmhas", "tox_apeach", "aihub_ethics", "toxicity"]:
        rows = [json.loads(l) for l in open(f"{EVAL}/{name}.jsonl") if l.strip()]
        texts = [r["text"] for r in rows]
        labels = [int(r["label"]) for r in rows]
        m = metrics(ptoxic(texts), labels)
        report[name] = m
        print(f"  {name:14} recall={m['recall']}  fpr={m['fpr']}")
    med = load_med()
    medp = ptoxic(med)
    mfpr = round(sum(p > THR for p in medp) / len(med) * 100, 2)
    report["medical_fpr"] = mfpr
    print(f"  medical_FPR    = {mfpr}%")
    json.dump(report, open(OUT, "w"), ensure_ascii=False, indent=2)
    print(f"saved → {OUT}")


if __name__ == "__main__":
    main()
