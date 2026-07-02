"""ko-guard suite — Qwen3Guard 와 동일한 3축 셋으로 채점(head-to-head).

같은 qwen3guard_eval_input.jsonl 을 쓴다:
  · injection : ko-prompt-guard hybrid(룰 + v6 분류기)  → recall / FPR
  · toxicity  : ko-output-guard(룰 + KcELECTRA 통합)    → recall / FPR
  · medical   : ko-output-guard                          → FPR
"""
from __future__ import annotations

import json
import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

INP = "/data1/mk04/eval_external/qwen3guard_eval_input.jsonl"
V6 = "/data1/mk04/eval_external/ko_injection_guard_v8/final"
KC = "/data1/mk04/eval_external/unified_kc/final"
OUT = "/data1/mk04/eval_external/ko_guard_3axis_report.json"

rows = [json.loads(l) for l in open(INP) if l.strip()]


def by_axis(a):
    idx = [i for i, r in enumerate(rows) if r["axis"] == a]
    return [rows[i]["text"] for i in idx], np.array([rows[i]["label"] for i in idx])


def scores(model_dir, texts, bs=64, pos_index=None):
    tok = AutoTokenizer.from_pretrained(model_dir)
    net = AutoModelForSequenceClassification.from_pretrained(model_dir).eval()
    outs = []
    with torch.no_grad():
        for i in range(0, len(texts), bs):
            e = tok(texts[i:i + bs], padding=True, truncation=True, max_length=128, return_tensors="pt")
            logits = net(**e).logits
            if pos_index is not None:  # 이진 softmax positive prob
                outs.append(torch.softmax(logits, -1)[:, pos_index].numpy())
            else:                       # multi-label sigmoid
                outs.append(torch.sigmoid(logits).numpy())
    return np.concatenate(outs)


def rc_fpr(flag, gold):
    tp = int((flag & (gold == 1)).sum()); fn = int((~flag & (gold == 1)).sum())
    fp = int((flag & (gold == 0)).sum()); tn = int((~flag & (gold == 0)).sum())
    rec = round(tp / (tp + fn) * 100, 1) if tp + fn else None
    fpr = round(fp / (fp + tn) * 100, 1) if fp + tn else None
    return {"recall": rec, "fpr": fpr, "n_pos": tp + fn, "n_neg": fp + tn}


rep = {"suite": "ko-guard (prompt+output)"}

# --- injection: ko-prompt-guard 룰 + v6 분류기 (hybrid) ---
import sys
sys.path.insert(0, "/data1/mk04/eval_external/modak_pub/ko-prompt-guard/src")
from ko_prompt_guard import Guard as PGuard, Verdict as PVerdict
itx, iy = by_axis("injection")
pg = PGuard()
rule_flag = np.array([pg.check(t).verdict is not PVerdict.ALLOW for t in itx])
clf = scores(V6, itx, pos_index=1) > 0.5
rep["injection"] = rc_fpr(rule_flag | clf, iy)
print("[injection]", rep["injection"], flush=True)

# --- toxicity: ko-output-guard 룰 + KcELECTRA ---
sys.path.insert(0, "/data1/mk04/eval_external/modak_pub/ko-output-guard/src")
from ko_output_guard import Guard as OGuard, Verdict as OVerdict
ttx, ty = by_axis("toxicity")
og = OGuard()
orule = np.array([og.check(t).verdict is not OVerdict.SAFE for t in ttx])
thr = np.array([0.6, 0.5, 0.5, 0.5])
kc = (scores(KC, ttx) > thr).any(axis=1)
rep["toxicity"] = rc_fpr(orule | kc, ty)
print("[toxicity]", rep["toxicity"], flush=True)

# --- medical: ko-output-guard FPR ---
mtx, my = by_axis("medical")
mrule = np.array([og.check(t).verdict is not OVerdict.SAFE for t in mtx])
mkc = (scores(KC, mtx) > thr).any(axis=1)
mflag = mrule | mkc
rep["medical"] = {"fpr": round(float(mflag.mean() * 100), 2), "n": len(mtx)}
print("[medical]", rep["medical"], flush=True)

json.dump(rep, open(OUT, "w"), ensure_ascii=False, indent=2)
print("KOGUARD_3AXIS_DONE")
