"""Opt-in Tier-2 reviewers — Guard(tier2={Category.X: fn}) 의 ``fn:(str)->bool`` 레퍼런스.

결정론 룰은 *명시적* 위반만 고정밀로 잡는다(예: HATE 는 슬러·노골 선동만, AI-Hub 외부셋
recall 9.3%). 의미·암시·완곡 위반의 recall 은 모델 영역(README "외부 검증"). ``EmbeddingTier2``
는 입력을 임베딩(기본 bge-m3)해 *알려진 위반 앵커* 와 top-k 코사인 유사도로 risk 를 매기고,
threshold 초과면 위반으로 본다. Guard 의 Tier-2 훅에 꽂으면 두 역할을 한다:

  · VET   : ambiguous=True 인 룰 히트를 confirm/deny → FP 제거
  · RECALL: 룰이 못 잡은 카테고리를 보강 → 암시적 위반 recall ↑

ko-prompt-guard 의 ``EmbeddingReviewer`` 와 같은 패턴. 인코더 주입 가능(``encode=``)이라
코어는 ML-free; 기본 bge-m3 백엔드는 ``pip install ko-output-guard[embedding]`` 로 lazy 로드.
advisory 설계 — 단독으로 hard-block 하지 말고 사람/추가 게이트와 함께.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path

Encoder = Callable[[Sequence[str]], "list[list[float]]"]

_ANCHOR_DIR = Path(__file__).resolve().parent / "data"


def default_hate_anchors() -> list[str]:
    """번들 HATE 앵커 — 보호집단 대상 비하·선동·비인간화의 *대표 표현*(EN+KO, 손작성).

    탐지용 negative 예시다(슬러/선동/암시 비하). 프로덕션은 자체 레드팀/라벨 코퍼스로
    ``EmbeddingTier2(anchors=...)`` 확장 권장.
    """
    return list(json.loads((_ANCHOR_DIR / "hate_anchors.json").read_text("utf-8"))["anchors"])


def _cosine_topk_mean(vec: list[float], mat: list[list[float]], k: int) -> float:
    sims = [sum(a * b for a, b in zip(vec, row)) for row in mat]
    if not sims:
        return 0.0
    sims.sort(reverse=True)
    k = max(1, min(k, len(sims)))
    return sum(sims[:k]) / k


class EmbeddingTier2:
    """카테고리 무관 임베딩 Tier-2 confirmer. ``__call__(text)->bool`` 로 Guard.tier2 에 주입.

    risk = 입력 ↔ 앵커 top-k 코사인 평균. ``threshold`` 초과면 True(위반 있음).
    """

    def __init__(
        self,
        anchors: Sequence[str],
        *,
        encode: Encoder | None = None,
        threshold: float = 0.60,
        top_k: int = 3,
        model: str = "BAAI/bge-m3",
        max_length: int = 256,
    ) -> None:
        self.anchors = list(anchors)
        if not self.anchors:
            raise ValueError("EmbeddingTier2 needs at least one anchor")
        self.threshold = threshold
        self.top_k = top_k
        self._model = model
        self._max_length = max_length
        self._encode = encode
        self._anchor_emb: list[list[float]] | None = None

    def _ensure(self) -> None:
        if self._encode is None:
            self._encode = make_bge_encoder(self._model, max_length=self._max_length)
        if self._anchor_emb is None:
            self._anchor_emb = [list(map(float, v)) for v in self._encode(self.anchors)]

    def risk(self, text: str) -> float:
        if not isinstance(text, str) or not text.strip():
            return 0.0
        self._ensure()
        assert self._encode is not None and self._anchor_emb is not None
        vec = list(map(float, self._encode([text])[0]))
        return max(0.0, min(1.0, _cosine_topk_mean(vec, self._anchor_emb, self.top_k)))

    def __call__(self, text: str) -> bool:
        return self.risk(text) > self.threshold


def make_hate_tier2(threshold: float = 0.60, **kw) -> EmbeddingTier2:
    """기본 HATE 앵커로 임베딩 Tier-2 confirmer 생성.

    ⚠️ 임베딩-유사도는 *주제*는 잡아도 *입장/의도* 분리가 약해 **HATE 에는 recall↑ 시
    FPR 이 급증**한다(실측: KMHAS thr0.62 recall 48%/FPR 22%). HATE/TOXICITY 처럼 같은
    주제의 정상·혐오가 임베딩 이웃인 카테고리는 **학습 분류기(``ClassifierTier2``)** 가 맞다
    (injection 같이 공격 *구조*가 분리되는 카테고리에만 임베딩-sim 권장). README "하이브리드" 참조.
    """
    return EmbeddingTier2(default_hate_anchors(), threshold=threshold, **kw)


class ClassifierTier2:
    """학습된 HF 시퀀스 분류기 기반 Tier-2 confirmer — ``__call__(text)->bool``.

    HATE/TOXICITY 처럼 의도/입장 판단이 핵심인 카테고리용(임베딩-sim 보다 강함). 모델은
    bring-your-own(레포에 가중치 미포함). ``positive_index`` 클래스 확률 > ``threshold`` 면 True.
    예: klue/roberta 를 혐오/욕설 라벨로 파인튜닝(README '재현 레시피') → ``ClassifierTier2(model_dir)``.
    """

    def __init__(
        self,
        model_dir: str,
        *,
        threshold: float = 0.5,
        positive_index: int = 1,
        max_length: int = 256,
        device: str | None = None,
    ) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "ClassifierTier2 needs torch+transformers: pip install ko-output-guard[embedding]."
            ) from e
        self._torch = torch
        self.threshold = threshold
        self.positive_index = positive_index
        self.max_length = max_length
        self._dev = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self._tok = AutoTokenizer.from_pretrained(model_dir)
        self._net = AutoModelForSequenceClassification.from_pretrained(model_dir).eval().to(self._dev)

    def prob(self, text: str) -> float:
        if not isinstance(text, str) or not text.strip():
            return 0.0
        torch = self._torch
        with torch.no_grad():
            enc = self._tok(text, truncation=True, max_length=self.max_length,
                            return_tensors="pt").to(self._dev)
            p = torch.softmax(self._net(**enc).logits[0], dim=-1)
            return float(p[self.positive_index])

    def __call__(self, text: str) -> bool:
        return self.prob(text) > self.threshold


def make_bge_encoder(
    model: str = "BAAI/bge-m3",
    *,
    device: str | None = None,
    max_length: int = 256,
    batch_size: int = 64,
) -> Encoder:
    """Lazy bge-m3 인코더 → L2-정규화 dense(CLS) 임베딩. torch+transformers 필요(opt-in extra)."""
    try:
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "EmbeddingTier2 default backend needs torch+transformers: "
            "pip install ko-output-guard[embedding] (or pass encode=...)."
        ) from e

    dev = device or ("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(model)
    net = AutoModel.from_pretrained(model).eval().to(dev)

    @torch.no_grad()
    def encode(texts: Sequence[str]) -> list[list[float]]:
        out: list[list[float]] = []
        texts = list(texts)
        for i in range(0, len(texts), batch_size):
            b = texts[i : i + batch_size]
            enc = tok(b, padding=True, truncation=True, max_length=max_length,
                      return_tensors="pt").to(dev)
            h = net(**enc).last_hidden_state[:, 0]
            h = torch.nn.functional.normalize(h, dim=-1)
            out.extend(h.float().cpu().tolist())
        return out

    return encode
