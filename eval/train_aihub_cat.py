"""AI-Hub 147 윤리검증으로 카테고리-특정 분류기(klue/roberta) 학습 — SEXUAL/VIOLENCE 등.

positive = 해당 type ∈ sentence.types, negative = 그 외(clean + 다른 immoral). 카테고리-특정
(immoral-vs-clean 아님)이라 SEXUAL 분류기가 폭력·혐오를 SEXUAL로 오인 안 함. 대화 단위 80/20
split(문장 누수 방지). 사용: train_aihub_cat.py SEXUAL
"""
import sys, glob, json, random
import numpy as np, torch
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          DataCollatorWithPadding, Trainer, TrainingArguments)

from _paths import eval_path

random.seed(13)
CAT = sys.argv[1]
MODEL = "klue/roberta-base"
BASE = (eval_path("aihub_ethics") + "/147.텍스트_윤리검증_데이터/"
        "01.데이터/2.Validation/라벨링데이터/aihub/extracted")

convs = []
for f in glob.glob(BASE + "/**/*.json", recursive=True):
    for conv in json.load(open(f)):
        rows = []
        for s in conv.get("sentences", []):
            t = (s.get("text") or "").strip()
            if not t:
                continue
            y = 1 if CAT in set(s.get("types", [])) else 0
            rows.append((t, y))
        if rows:
            convs.append(rows)
random.shuffle(convs)
cut = int(len(convs) * 0.8)
tr = [r for c in convs[:cut] for r in c]
te = [r for c in convs[cut:] for r in c]
x_tr, y_tr = [a for a, _ in tr], [b for _, b in tr]
x_te, y_te = [a for a, _ in te], [b for _, b in te]
print(f"[{CAT}] train pos={sum(y_tr)}/{len(y_tr)}  test pos={sum(y_te)}/{len(y_te)}")

tok = AutoTokenizer.from_pretrained(MODEL)
class DS(torch.utils.data.Dataset):
    def __init__(s, x, y): s.e = tok(x, truncation=True, max_length=128); s.y = y
    def __len__(s): return len(s.y)
    def __getitem__(s, i):
        d = {k: v[i] for k, v in s.e.items()}; d["labels"] = s.y[i]; return d

model = AutoModelForSequenceClassification.from_pretrained(MODEL, num_labels=2)
out = eval_path(f"{CAT.lower()}_model")
args = TrainingArguments(output_dir=out, per_device_train_batch_size=32, num_train_epochs=3,
                         learning_rate=2e-5, fp16=True, logging_steps=100, save_strategy="no", report_to=[])
trn = Trainer(model=model, args=args, train_dataset=DS(x_tr, y_tr),
              data_collator=DataCollatorWithPadding(tok))
trn.train()
model.save_pretrained(f"{out}/final"); tok.save_pretrained(f"{out}/final")
pred = trn.predict(DS(x_te, y_te)); yp = np.asarray(pred.predictions).argmax(-1); ya = np.asarray(y_te)
tp = int(((yp == 1) & (ya == 1)).sum()); fp = int(((yp == 1) & (ya == 0)).sum()); fn = int(((yp == 0) & (ya == 1)).sum())
rec = tp/(tp+fn)*100 if tp+fn else 0; prec = tp/(tp+fp)*100 if tp+fp else 0
print(f"[{CAT}] TEST(held-out conv) recall {rec:.1f}% precision {prec:.1f}%")
print(f"DONE_TRAIN_{CAT}")
