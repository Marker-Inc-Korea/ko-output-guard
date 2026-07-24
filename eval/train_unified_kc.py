import os
"""통합 multi-label 모더레이션 v2 — base를 KcELECTRA로 교체 (혐오/욕설 in-domain).

기존 unified=klue/roberta-base. KcELECTRA(beomi/KcELECTRA-base-v2022, MIT)는 네이버 댓글로
사전학습돼 한국어 혐오/욕설에 in-domain — recall↑·FPR↓ 기대. masked-BCE 동일.
SEXUAL0 VIOLENCE1 HATE2 TOXICITY3. 외부 평가셋으로 klue/roberta 대비 직접 비교.
"""
import csv, glob, json, os, random
import numpy as np, torch
import torch.nn.functional as Fnn
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments)

from _paths import EVAL_ROOT, KO_PII_EVAL_ROOT, eval_path

random.seed(13)
CATS = ["SEXUAL", "VIOLENCE", "HATE", "TOXICITY"]
MODEL = os.environ.get("BASE_MODEL", "beomi/KcELECTRA-base-v2022")
OUTDIR = os.environ.get("OUT_DIR", eval_path("unified_kc"))
D = str(EVAL_ROOT)
AHUB = f"{D}/aihub_ethics/147.텍스트_윤리검증_데이터/01.데이터/2.Validation/라벨링데이터/aihub/extracted"
EVAL = str(KO_PII_EVAL_ROOT)
QTAOA = os.environ.get("KO_GUARD_BENIGN_CORPUS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures/benign_ko_sample.jsonl"))
HATE_COLS = ["여성/가족", "남성", "성소수자", "인종/국적", "연령", "지역", "종교", "기타 혐오"]
print(f"BASE={MODEL}")

# ---- AI-Hub: SEXUAL/VIOLENCE 라벨 ----
ah_convs = []
for f in glob.glob(AHUB + "/**/*.json", recursive=True):
    for conv in json.load(open(f)):
        rows = []
        for s in conv.get("sentences", []):
            t = (s.get("text") or "").strip()
            if not t: continue
            ty = set(s.get("types", []))
            rows.append((t, [1.0 if "SEXUAL" in ty else 0.0, 1.0 if "VIOLENCE" in ty else 0.0, -1.0, -1.0]))
        if rows: ah_convs.append(rows)
random.shuffle(ah_convs)
cut = int(len(ah_convs) * 0.8)
ah_tr = [r for c in ah_convs[:cut] for r in c]; ah_te = [r for c in ah_convs[cut:] for r in c]

def unsmile(split):
    rows = list(csv.DictReader(open(f"{D}/unsmile_{split}_v1.0.tsv", encoding="utf-8"), delimiter="\t"))
    return [(r["문장"], [-1.0, -1.0, 1.0 if any(r.get(c)=="1" for c in HATE_COLS) else 0.0,
                         0.0 if r.get("clean")=="1" else 1.0]) for r in rows]
us_tr = unsmile("train"); us_va = unsmile("valid")
train = ah_tr + us_tr; random.shuffle(train)
print(f"train={len(train)} (AI-Hub {len(ah_tr)} + unsmile {len(us_tr)})")

tok = AutoTokenizer.from_pretrained(MODEL)
class DS(torch.utils.data.Dataset):
    def __init__(s, data): s.x=[a for a,_ in data]; s.y=[b for _,b in data]; s.e=tok(s.x, truncation=True, max_length=128)
    def __len__(s): return len(s.y)
    def __getitem__(s, i):
        d={k:v[i] for k,v in s.e.items()}; d["labels"]=s.y[i]; return d
def collate(feats):
    labels=torch.tensor([f.pop("labels") for f in feats], dtype=torch.float)
    b=tok.pad(feats, padding=True, return_tensors="pt"); b["labels"]=labels; return b
class MaskedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kw):
        labels=inputs.pop("labels"); out=model(**inputs)
        mask=(labels!=-1.0).float(); target=labels.clamp(min=0.0)
        loss=Fnn.binary_cross_entropy_with_logits(out.logits, target, reduction="none")
        loss=(loss*mask).sum()/mask.sum().clamp(min=1.0)
        return (loss,out) if return_outputs else loss

model = AutoModelForSequenceClassification.from_pretrained(MODEL, num_labels=len(CATS))
args = TrainingArguments(output_dir=OUTDIR, per_device_train_batch_size=32, num_train_epochs=3,
    learning_rate=2e-5, fp16=True, logging_steps=200, save_strategy="no", report_to=[])
MaskedTrainer(model=model, args=args, train_dataset=DS(train), data_collator=collate).train()
model.save_pretrained(f"{OUTDIR}/final"); tok.save_pretrained(f"{OUTDIR}/final")

@torch.no_grad()
def probs(texts, bs=64):
    o=[]
    for i in range(0,len(texts),bs):
        e=tok(texts[i:i+bs], padding=True, truncation=True, max_length=128, return_tensors="pt").to(model.device)
        o.append(torch.sigmoid(model(**e).logits).cpu().numpy())
    return np.concatenate(o)

def hate_tox_flag(texts, thr=0.5):
    """HATE(2)/TOXICITY(3) 최대 — bench_output 의 ko_unified 정의와 동일."""
    p = probs(texts); return (np.maximum(p[:,2], p[:,3]) > thr)

def metrics(name, texts, labels, thr=0.5):
    f = hate_tox_flag(texts, thr); y = np.asarray(labels)
    tp=int(((f==1)&(y==1)).sum()); fp=int(((f==1)&(y==0)).sum()); fn=int(((f==0)&(y==1)).sum()); tn=int(((f==0)&(y==0)).sum())
    rec=tp/(tp+fn)*100 if tp+fn else None; fpr=fp/(fp+tn)*100 if fp+tn else None
    print(f"[{name:14}] recall={None if rec is None else round(rec,1)} FPR={None if fpr is None else round(fpr,1)} (n={len(texts)})")
    return {"recall": rec and round(rec,1), "fpr": fpr and round(fpr,1)}

print(f"\n=== {MODEL} 외부 평가 (klue/roberta 기존: KMHAS 95.6/49.6, APEACH 89.2/21.2, AIHub 83.2/24, tox 96/32.8, K-HATERS 88.6/42.6, 의료 1.0) ===")
rep = {"base": MODEL}
for name in ["tox_kmhas", "tox_apeach", "aihub_ethics", "toxicity", "khaters"]:
    rows = [json.loads(l) for l in open(f"{EVAL}/{name}.jsonl") if l.strip()]
    rep[name] = metrics(name, [r["text"] for r in rows], [int(r["label"]) for r in rows])
# 의료 FPR
med=[]
for line in open(QTAOA):
    if not line.strip(): continue
    r=json.loads(line); a=[m for m in r.get("messages",[]) if m.get("role")=="assistant" and m.get("content")]
    if a and len(a[-1]["content"].strip())>=40: med.append(a[-1]["content"].strip()[:600])
    if len(med)>=200: break
mfpr = round(float(hate_tox_flag(med).mean()*100), 2)
rep["medical_fpr"] = mfpr
print(f"[medical_fpr   ] {mfpr}%")
json.dump(rep, open(f"{D}/unified_kc_report.json","w"), ensure_ascii=False, indent=2)
print("DONE_UNIFIED_KC")
