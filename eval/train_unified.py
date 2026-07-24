"""통합 multi-label 모더레이션 모델 1개 — SEXUAL/VIOLENCE/HATE/TOXICITY.

데이터셋이 카테고리별로 달라(SEXUAL/VIOLENCE=AI-Hub, HATE/TOXICITY=unsmile) **masked BCE**로
부분 라벨 학습: 각 행은 라벨이 있는 카테고리만 loss 에 기여(-1=mask=모름). 한 모델로 4범주를
동시에 강하게 — 분리/약한-AI-Hub-HATE 문제 해소. 라벨 인덱스: SEXUAL0 VIOLENCE1 HATE2 TOXICITY3.
"""
import csv, glob, json, random
import numpy as np, torch
import torch.nn.functional as Fnn
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments)

from _paths import EVAL_ROOT, pii_path

random.seed(13)
CATS = ["SEXUAL", "VIOLENCE", "HATE", "TOXICITY"]
MODEL = "klue/roberta-base"
D = str(EVAL_ROOT)
AHUB = f"{D}/aihub_ethics/147.텍스트_윤리검증_데이터/01.데이터/2.Validation/라벨링데이터/aihub/extracted"
HATE_COLS = ["여성/가족", "남성", "성소수자", "인종/국적", "연령", "지역", "종교", "기타 혐오"]

# ---- AI-Hub: SEXUAL/VIOLENCE/HATE 라벨, TOXICITY=mask ----
ah_convs = []
for f in glob.glob(AHUB + "/**/*.json", recursive=True):
    for conv in json.load(open(f)):
        rows = []
        for s in conv.get("sentences", []):
            t = (s.get("text") or "").strip()
            if not t:
                continue
            ty = set(s.get("types", []))
            rows.append((t, [
                1.0 if "SEXUAL" in ty else 0.0,
                1.0 if "VIOLENCE" in ty else 0.0,
                -1.0,  # HATE는 unsmile로(AI-Hub 마스킹)
                -1.0,  # TOXICITY는 unsmile로(AI-Hub 마스킹)
            ]))
        if rows:
            ah_convs.append(rows)
random.shuffle(ah_convs)
cut = int(len(ah_convs) * 0.8)
ah_tr = [r for c in ah_convs[:cut] for r in c]
ah_te = [r for c in ah_convs[cut:] for r in c]

# ---- unsmile: HATE/TOXICITY 라벨, SEXUAL/VIOLENCE=mask ----
def unsmile(split):
    rows = list(csv.DictReader(open(f"{D}/unsmile_{split}_v1.0.tsv", encoding="utf-8"), delimiter="\t"))
    out = []
    for r in rows:
        h = 1.0 if any(r.get(c) == "1" for c in HATE_COLS) else 0.0
        tox = 0.0 if r.get("clean") == "1" else 1.0  # broad toxic(not clean)=tox_model 정의
        out.append((r["문장"], [-1.0, -1.0, h, tox]))  # sexual/violence unknown
    return out
us_tr = unsmile("train"); us_va = unsmile("valid")

train = ah_tr + us_tr
random.shuffle(train)
print(f"train={len(train)} (AI-Hub {len(ah_tr)} + unsmile {len(us_tr)})")

tok = AutoTokenizer.from_pretrained(MODEL)
class DS(torch.utils.data.Dataset):
    def __init__(s, data): s.x = [a for a, _ in data]; s.y = [b for _, b in data]; s.e = tok(s.x, truncation=True, max_length=128)
    def __len__(s): return len(s.y)
    def __getitem__(s, i):
        d = {k: v[i] for k, v in s.e.items()}; d["labels"] = s.y[i]; return d
def collate(feats):
    labels = torch.tensor([f.pop("labels") for f in feats], dtype=torch.float)
    batch = tok.pad(feats, padding=True, return_tensors="pt"); batch["labels"] = labels; return batch

class MaskedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kw):
        labels = inputs.pop("labels")
        out = model(**inputs)
        mask = (labels != -1.0).float()
        target = labels.clamp(min=0.0)
        loss = Fnn.binary_cross_entropy_with_logits(out.logits, target, reduction="none")
        loss = (loss * mask).sum() / mask.sum().clamp(min=1.0)
        return (loss, out) if return_outputs else loss

model = AutoModelForSequenceClassification.from_pretrained(MODEL, num_labels=len(CATS))
args = TrainingArguments(output_dir=f"{D}/unified_model", per_device_train_batch_size=32,
    num_train_epochs=3, learning_rate=2e-5, fp16=True, logging_steps=200, save_strategy="no", report_to=[])
trn = MaskedTrainer(model=model, args=args, train_dataset=DS(train), data_collator=collate)
trn.train()
model.save_pretrained(f"{D}/unified_model/final"); tok.save_pretrained(f"{D}/unified_model/final")

@torch.no_grad()
def probs(texts, bs=64):
    o = []
    for i in range(0, len(texts), bs):
        e = tok(texts[i:i+bs], padding=True, truncation=True, max_length=128, return_tensors="pt").to(model.device)
        o.append(torch.sigmoid(model(**e).logits).cpu().numpy())
    return np.concatenate(o)

def score(name, idx, texts, ya, thr=0.5):
    p = probs(texts)[:, idx]; yp = (p > thr).astype(int); yc = np.asarray(ya).astype(int)
    tp = int(((yp==1)&(yc==1)).sum()); fp = int(((yp==1)&(yc==0)).sum()); fn = int(((yp==0)&(yc==1)).sum())
    rec = tp/(tp+fn)*100 if tp+fn else 0; prec = tp/(tp+fp)*100 if tp+fp else 0
    print(f"  {name:9} recall {rec:.1f}%  precision {prec:.1f}%  (n_pos={tp+fn})")

print("\n=== 통합 1모델 per-category (held-out) — 분리모델 대비 ===")
print("(분리: SEXUAL 50.3/71.1, VIOLENCE 59.7/58.8, HATE(unsmile)90.8/87.9, TOXICITY~91.6)")
# SEXUAL/VIOLENCE: AI-Hub test
score("SEXUAL", 0, [a for a,_ in ah_te], [b[0] for _,b in ah_te])
score("VIOLENCE", 1, [a for a,_ in ah_te], [b[1] for _,b in ah_te])
# HATE/TOXICITY: unsmile valid
score("HATE", 2, [a for a,_ in us_va], [b[2] for _,b in us_va])
score("TOXICITY", 3, [a for a,_ in us_va], [b[3] for _,b in us_va])
# HATE: KMHAS cross-dataset
km = [
    json.loads(line)
    for line in open(pii_path("tox_kmhas.jsonl"))
    if line.strip()
]
score("HATE(KMHAS)", 2, [r["text"] for r in km], [1 if str(r.get("label"))=="1" else 0 for r in km])
print("DONE_UNIFIED")
