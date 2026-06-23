"""unsmile HATE 분류기(klue/roberta-base) — ko-output-guard HATE Tier-2 용.

핵심: 보호집단 혐오 카테고리(여성/가족·남성·성소수자·인종/국적·연령·지역·종교·기타혐오)==1 → 1,
그 외(clean OR 악플/욕설만)→0. 욕설-only 를 negative 로 둬 toxicity≠hate 를 학습(임베딩-sim/
toxicity-clf 가 못 푼 부분). 학습 후 final/ 저장.
"""
import csv, sys
import numpy as np, torch
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          DataCollatorWithPadding, Trainer, TrainingArguments)

D = "/data1/mk04/eval_external"
MODEL = "klue/roberta-base"
HATE_COLS = ["여성/가족", "남성", "성소수자", "인종/국적", "연령", "지역", "종교", "기타 혐오"]


def load(split):
    with open(f"{D}/unsmile_{split}_v1.0.tsv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    x = [r["문장"] for r in rows]
    y = [1 if any(r.get(c) == "1" for c in HATE_COLS) else 0 for r in rows]
    return x, y


def main():
    tok = AutoTokenizer.from_pretrained(MODEL)

    class DS(torch.utils.data.Dataset):
        def __init__(self, x, y): self.e = tok(x, truncation=True, max_length=128); self.y = y
        def __len__(self): return len(self.y)
        def __getitem__(self, i):
            d = {k: v[i] for k, v in self.e.items()}; d["labels"] = self.y[i]; return d

    x_tr, y_tr = load("train"); x_va, y_va = load("valid")
    print(f"train hate={sum(y_tr)}/{len(y_tr)}  valid hate={sum(y_va)}/{len(y_va)}")
    model = AutoModelForSequenceClassification.from_pretrained(MODEL, num_labels=2)
    args = TrainingArguments(output_dir=f"{D}/hate_model", per_device_train_batch_size=32,
                             num_train_epochs=3, learning_rate=2e-5, fp16=True,
                             logging_steps=50, save_strategy="no", report_to=[])
    tr = Trainer(model=model, args=args, train_dataset=DS(x_tr, y_tr),
                 data_collator=DataCollatorWithPadding(tok))
    tr.train()
    model.save_pretrained(f"{D}/hate_model/final"); tok.save_pretrained(f"{D}/hate_model/final")
    pred = tr.predict(DS(x_va, y_va))
    yp = np.asarray(pred.predictions).argmax(-1); ya = np.asarray(y_va)
    tp = int(((yp == 1) & (ya == 1)).sum()); fp = int(((yp == 1) & (ya == 0)).sum())
    fn = int(((yp == 0) & (ya == 1)).sum())
    rec = tp/(tp+fn)*100 if tp+fn else 0; prec = tp/(tp+fp)*100 if tp+fp else 0
    print(f"VALID(unsmile) hate recall {rec:.1f}% precision {prec:.1f}%")
    print("DONE_TRAIN_HATE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
