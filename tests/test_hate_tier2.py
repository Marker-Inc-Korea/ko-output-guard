"""EmbeddingTier2(HATE) — opt-in 임베딩 Tier-2 를 Guard.tier2 훅에 배선.

핵심 로직(앵커·top-k 코사인·threshold)은 주입 인코더로 ML 없이 검증. Guard 결합(VET:
ambiguous 룰히트 confirm/deny, RECALL: 암시 hate 보강)은 스텁 confirmer 로 검증.
실제 bge-m3 백엔드는 transformers 있을 때만 스모크.
"""
from __future__ import annotations

import math

import pytest

from ko_output_guard import (
    Category,
    EmbeddingTier2,
    Guard,
    Verdict,
    default_hate_anchors,
    make_hate_tier2,
)

_HATE_KW = ("열등", "박멸", "추방", "벌레", "기생충", "짐승", "종속", "역겹", "없애", "subhuman", "inferior")


def _fake_encode(texts):
    out = []
    for t in texts:
        lo = t.lower()
        a = 1.0 if any(k in lo for k in _HATE_KW) else 0.0
        b = 0.0 if a else 1.0
        n = math.hypot(a, b) or 1.0
        out.append([a / n, b / n])
    return out


_HATE_ANCHORS = ["그 인종은 열등하다", "장애인은 박멸해야 한다", "외국인은 추방해야 한다",
                 "여자는 남자한테 종속돼야 한다", "그들은 벌레 같은 존재다"]


# --- 번들 앵커 / 로직 -------------------------------------------------------------
def test_default_hate_anchors_loaded() -> None:
    a = default_hate_anchors()
    assert len(a) >= 30 and all(isinstance(x, str) and x.strip() for x in a)


def test_empty_anchors_rejected() -> None:
    with pytest.raises(ValueError):
        EmbeddingTier2([], encode=_fake_encode)


def test_risk_and_call_threshold() -> None:
    t2 = EmbeddingTier2(_HATE_ANCHORS, encode=_fake_encode, threshold=0.5)
    assert t2.risk("그 집단은 열등하고 박멸해야 할 벌레다") > 0.5
    assert t2.risk("오늘 점심은 김치찌개를 먹었다") < 0.5
    assert t2("그 집단은 열등하다") is True       # __call__ → bool (tier2 훅 시그니처)
    assert t2("좋은 아침입니다") is False


def test_call_returns_bool_for_tier2_hook() -> None:
    t2 = EmbeddingTier2(_HATE_ANCHORS, encode=_fake_encode)
    assert isinstance(t2("아무 문장"), bool)


# --- Guard 결합: VET (ambiguous hate 히트 confirm/deny) ---------------------------
_HATE_RULE_HIT = "장애인은 사회에서 박멸해야 한다"  # hate.py 시드 → HATE ambiguous


def test_rule_hate_hit_is_ambiguous() -> None:
    hv = [v for v in Guard().check(_HATE_RULE_HIT).violations if v.category is Category.HATE]
    assert hv and all(v.ambiguous for v in hv)


def test_tier2_deny_drops_ambiguous_hate() -> None:
    g = Guard(tier2={Category.HATE: lambda s: False})
    r = g.check(_HATE_RULE_HIT)
    assert not any(v.category is Category.HATE for v in r.violations)  # 모델 부정 → 드롭


def test_tier2_confirm_keeps_hate_block() -> None:
    g = Guard(tier2={Category.HATE: lambda s: True})
    assert g.check(_HATE_RULE_HIT).verdict is Verdict.BLOCK


# --- Guard 결합: RECALL (룰이 못 잡은 암시 hate 보강) ------------------------------
def test_tier2_recall_adds_hate_on_implicit() -> None:
    implicit = "그런 사람들은 원래 다 똑같아서 상종하면 안 돼"  # 슬러 없음 → 룰 미탐
    assert not any(v.category is Category.HATE for v in Guard().check(implicit).violations)
    g = Guard(tier2={Category.HATE: lambda s: True})  # 모델이 hate 로 판정
    assert any(v.code == "hate:tier2" for v in g.check(implicit).violations)


# --- 실제 bge-m3 스모크 -----------------------------------------------------------
def test_real_bge_hate_tier2_smoke() -> None:
    pytest.importorskip("transformers")
    pytest.importorskip("torch")
    t2 = make_hate_tier2(threshold=0.55)
    assert t2.risk("그 민족은 열등하고 더러우니 다 추방해야 한다") > t2.risk("어린이 영양 간식을 추천해줘")
