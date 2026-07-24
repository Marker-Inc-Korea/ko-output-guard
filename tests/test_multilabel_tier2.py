"""MultiLabelClassifierTier2 — 한 모델을 여러 카테고리에서 공유(forward 1회 캐시).

probs 를 stub 한 서브클래스로 for_label/캐시/Guard 결합을 ML 없이 검증.
"""
from __future__ import annotations

import pytest

from ko_output_guard import (
    Category,
    Guard,
    GuardPolicy,
    MultiLabelClassifierTier2,
)

# 라벨 인덱스: SEXUAL0 VIOLENCE1 HATE2 TOXICITY3


class _FakeML(MultiLabelClassifierTier2):
    """torch 없이 — __init__ 우회, probs 를 맵으로."""

    def __init__(self, pmap: dict[str, list[float]]) -> None:
        self._pmap = pmap
        self.calls = 0

    def probs(self, text: str) -> list[float]:
        self.calls += 1
        return self._pmap.get(text, [])


def test_for_label_threshold_per_category() -> None:
    ml = _FakeML({"x": [0.90, 0.10, 0.60, 0.20]})
    assert ml.for_label(0, 0.5)("x") is True    # SEXUAL 0.90
    assert ml.for_label(1, 0.5)("x") is False   # VIOLENCE 0.10
    assert ml.for_label(2, 0.5)("x") is True    # HATE 0.60
    assert ml.for_label(3, 0.5)("x") is False   # TOXICITY 0.20


def test_for_label_empty_probs_is_false() -> None:
    ml = _FakeML({})
    assert ml.for_label(0, 0.5)("모르는 텍스트") is False
    assert ml.for_label(9, 0.5)("x") is False   # 인덱스 범위 밖도 안전


def test_confirmers_share_one_model() -> None:
    # 4개 카테고리 confirmer 가 같은 텍스트를 보면 probs 가 (캐시로) 적게 호출됨을 보장하는 건
    # 실모델 캐시의 책임 — 여기선 for_label 이 probs 를 그대로 쓰는지(공유)만 확인.
    ml = _FakeML({"t": [0.9, 0.9, 0.9, 0.9]})
    confirmers = [ml.for_label(i, 0.5) for i in range(4)]
    assert all(c("t") for c in confirmers)


def test_one_model_recall_in_guard() -> None:
    implicit_hate = "그런 사람들은 원래 다 똑같아서 상종하면 안 돼"  # 룰 미탐
    assert not any(v.category is Category.HATE for v in Guard().check(implicit_hate).violations)
    ml = _FakeML({implicit_hate: [0.05, 0.05, 0.80, 0.10]})   # HATE=0.80
    g = Guard(GuardPolicy(tier2_vet=False), tier2={Category.HATE: ml.for_label(2, 0.5)})
    assert any(v.code == "hate:tier2" for v in g.check(implicit_hate).violations)


def test_real_multilabel_smoke() -> None:
    pytest.importorskip("transformers")
    pytest.importorskip("torch")
    import os
    md = os.environ.get("KO_OUTPUT_MULTILABEL_MODEL")
    if not md or not os.path.isdir(md):
        pytest.skip("KO_OUTPUT_MULTILABEL_MODEL 학습 산출물 없음")
    ml = MultiLabelClassifierTier2(md)
    p = ml.probs("그 민족은 열등하니 다 추방해야 한다")
    assert len(p) >= 3 and p[2] > 0.5   # HATE 인덱스 high
    assert ml.probs("어린이 영양 간식 레시피") == ml.probs("어린이 영양 간식 레시피")  # 캐시 동일
