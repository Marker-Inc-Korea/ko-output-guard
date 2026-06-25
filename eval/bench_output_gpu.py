"""task #15 GPU — ko-output-guard(통합분류기) vs kor_unsmile vs Detoxify vs Llama-Guard-3-1B.

ner_env에서 인코더 분류기 + Llama-Guard generative 추론 → flagged 확률/불리언 저장.
ko-output-guard 룰(pydantic)은 별도 CPU 스텝(bench_output_score.py).

핵심 = 한국어 hate/tox recall + **의료 도메인 FPR**(식약처 benign 의료문을 과탐하는가):
  시바⊂트레시바(Tresiba), 존나⊂세포페라존나트륨 등 부분문자열 오탐 위험.

출력: output_preds_gpu.json = {dataset: {texts,labels, ko_unified, kor_unsmile, detoxify, llama_guard}}
"""
from __future__ import annotations

import glob
import json

import torch
from transformers import (AutoModelForCausalLM, AutoModelForSequenceClassification,
                          AutoTokenizer)

EVAL = "/data1/mk04/projects/ko-pii/experiments/ko-output-guard/eval/external"
QTAOA = "/data1/mk04/medi/agentic_v3/data/qtaoa_combined.jsonl"
OUT = "/data1/mk04/eval_external/output_preds_gpu.json"
DEV = "cuda" if torch.cuda.is_available() else "cpu"

UNIFIED = "/data1/mk04/eval_external/unified_model/final"   # SEXUAL0 VIOLENCE1 HATE2 TOXICITY3
KOR_UNSMILE = "smilegate-ai/kor_unsmile"                    # 0-8 toxic, 9 clean (multi-label)
DETOX = "unitary/multilingual-toxic-xlm-roberta"           # {0:toxic}
LLAMA_GUARD = "meta-llama/Llama-Guard-3-1B"

# Llama-Guard는 느려(generative) 비용 큰 셋 제외 — 의료FPR + 대표 hate셋만
LG_DATASETS = {"medical_benign", "tox_kmhas"}


def load_datasets():
    ds = {}
    for name in ["tox_kmhas", "tox_apeach", "aihub_ethics", "toxicity"]:
        rows = [json.loads(l) for l in open(f"{EVAL}/{name}.jsonl") if l.strip()]
        ds[name] = ([r["text"] for r in rows], [int(r["label"]) for r in rows])
    # K-HATERS (humane-lab, native 한국어 hate, held-out — 2023, 신규 추가)
    kh = [json.loads(l) for l in open("/data1/mk04/eval_external/khaters_test.jsonl") if l.strip()]
    ds["khaters"] = ([r["text"] for r in kh], [int(r["label"]) for r in kh])
    # 의료 benign (qtaoa 최종 답변)
    med = []
    for line in open(QTAOA):
        if not line.strip():
            continue
        r = json.loads(line)
        a = [m for m in r.get("messages", []) if m.get("role") == "assistant" and m.get("content")]
        if a and len(a[-1]["content"].strip()) >= 40:
            med.append(a[-1]["content"].strip()[:600])
        if len(med) >= 200:
            break
    ds["medical_benign"] = (med, [0] * len(med))
    return ds


@torch.no_grad()
def enc_probs(model_dir, texts, reduce, bs=32):
    tok = AutoTokenizer.from_pretrained(model_dir, use_fast=True)
    net = AutoModelForSequenceClassification.from_pretrained(model_dir).eval().to(DEV)
    out = []
    for i in range(0, len(texts), bs):
        enc = tok(texts[i:i+bs], padding=True, truncation=True, max_length=256, return_tensors="pt").to(DEV)
        logits = net(**enc).logits
        out.extend(reduce(logits).cpu().tolist())
    del net; torch.cuda.empty_cache()
    return out


@torch.no_grad()
def llama_guard_unsafe(texts, bs=8):
    tok = AutoTokenizer.from_pretrained(LLAMA_GUARD, use_fast=True)
    net = AutoModelForCausalLM.from_pretrained(LLAMA_GUARD, torch_dtype=torch.bfloat16).eval().to(DEV)
    flags = []
    for t in texts:
        msgs = [{"role": "user", "content": "다음 답변이 안전한가요?"},
                {"role": "assistant", "content": t}]
        ids = tok.apply_chat_template(msgs, return_tensors="pt").to(DEV)
        gen = net.generate(ids, max_new_tokens=12, do_sample=False, pad_token_id=tok.eos_token_id)
        ans = tok.decode(gen[0][ids.shape[-1]:], skip_special_tokens=True).strip().lower()
        flags.append(1.0 if ans.startswith("unsafe") else 0.0)
    del net; torch.cuda.empty_cache()
    return flags


def main():
    ds = load_datasets()
    preds = {}
    for name, (texts, labels) in ds.items():
        preds[name] = {"texts": texts, "labels": labels, "n": len(texts)}
        # 각 모델 best-effort — 토크나이저 의존성(sentencepiece/tiktoken) 결손 시 skip
        for key, md, red in [
            ("ko_unified", UNIFIED, lambda lg: torch.sigmoid(lg[:, [2, 3]]).max(-1).values),
            ("kor_unsmile", KOR_UNSMILE, lambda lg: 1.0 - torch.sigmoid(lg[:, 9])),
            ("detoxify", DETOX, lambda lg: torch.sigmoid(lg[:, 0])),
        ]:
            try:
                preds[name][key] = enc_probs(md, texts, red)
            except Exception as e:
                print(f"  [{key} skip] {repr(e)[:90]}", flush=True)
        if name in LG_DATASETS:
            try:
                preds[name]["llama_guard"] = llama_guard_unsafe(texts)
            except Exception as e:
                print(f"  [llama_guard skip] {repr(e)[:100]}", flush=True)
        print(f"[{name}] done n={len(texts)}", flush=True)
    json.dump(preds, open(OUT, "w"))
    print(f"saved → {OUT}")


if __name__ == "__main__":
    main()
