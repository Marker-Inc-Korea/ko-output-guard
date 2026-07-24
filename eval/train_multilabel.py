"""한 모델 multi-label(SEXUAL/VIOLENCE/HATE 동시) vs 분리 모델 비교용 — 동일 conv split(seed13)."""
import glob, json, random
import numpy as np, torch
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments)

from _paths import eval_path

random.seed(13)
CATS = ["SEXUAL", "VIOLENCE", "HATE"]
MODEL = "klue/roberta-base"
BASE = (eval_path("aihub_ethics") + "/147.텍스트_윤리검증_데이터/"
        "01.데이터/2.Validation/라벨링데이터/aihub/extracted")
convs = []
for f in glob.glob(BASE + "/**/*.json", recursive=True):
    for conv in json.load(open(f)):
        rows = []
        for s in conv.get("sentences", []):
            t = (s.get("text") or "").strip()
            if not t: continue
            ty = set(s.get("types", []))
            rows.append((t, [1.0 if c in ty else 0.0 for c in CATS]))
        if rows: convs.append(rows)
random.shuffle(convs)
cut = int(len(convs)*0.8)
tr = [r for c in convs[:cut] for r in c]; te = [r for c in convs[cut:] for r in c]
x_tr, y_tr = [a for a,_ in tr], [b for _,b in tr]
x_te, y_te = [a for a,_ in te], [b for _,b in te]
print(f"train={len(x_tr)} test={len(x_te)}  per-cat pos(test):",
      {CATS[i]: int(sum(r[i] for r in y_te)) for i in range(len(CATS))})
tok = AutoTokenizer.from_pretrained(MODEL)
def collate(feats):
    labels=torch.tensor([f.pop("labels") for f in feats],dtype=torch.float)
    batch=tok.pad(feats,padding=True,return_tensors="pt"); batch["labels"]=labels; return batch
class DS(torch.utils.data.Dataset):
    def __init__(s,x,y): s.e=tok(x,truncation=True,max_length=128); s.y=y
    def __len__(s): return len(s.y)
    def __getitem__(s,i):
        d={k:v[i] for k,v in s.e.items()}; d["labels"]=s.y[i]; return d
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL, num_labels=len(CATS), problem_type="multi_label_classification")
args = TrainingArguments(output_dir=eval_path("multilabel_model"),
    per_device_train_batch_size=32, num_train_epochs=3, learning_rate=2e-5, fp16=True,
    logging_steps=100, save_strategy="no", report_to=[])
trn = Trainer(model=model, args=args, train_dataset=DS(x_tr,y_tr),
              data_collator=collate)
trn.train()
model.save_pretrained(eval_path("multilabel_model", "final"))
tok.save_pretrained(eval_path("multilabel_model", "final"))
pred = trn.predict(DS(x_te,y_te))
probs = 1/(1+np.exp(-np.asarray(pred.predictions)))  # sigmoid
ya = np.asarray(y_te)
print("\n=== multi-label(한 모델) per-category (thr 0.5) ===")
print("(비교: 분리모델 SEXUAL recall50.3/prec71.1, VIOLENCE recall59.7/prec58.8)")
for i,c in enumerate(CATS):
    yp = (probs[:,i]>0.5).astype(int); yc = ya[:,i].astype(int)
    tp=int(((yp==1)&(yc==1)).sum()); fp=int(((yp==1)&(yc==0)).sum()); fn=int(((yp==0)&(yc==1)).sum())
    rec=tp/(tp+fn)*100 if tp+fn else 0; prec=tp/(tp+fp)*100 if tp+fp else 0
    print(f"  {c:9} recall {rec:.1f}%  precision {prec:.1f}%")
print("DONE_MULTILABEL")
