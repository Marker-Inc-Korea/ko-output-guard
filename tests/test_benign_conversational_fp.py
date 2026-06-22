"""Benign casual-conversation FP suite (precision on non-adversarial traffic).

The headline TOXICITY FPR is measured on adversarial/balanced benchmark sets and
understates casual-conversation false positives. This file pins the casual cases as
regressions: benign casual praise/slang must stay SAFE, and must never BLOCK.
"""
from __future__ import annotations

import pytest

from ko_output_guard import Guard, Verdict

G = Guard()


def _v(t: str) -> Verdict:
    return G.check(t).verdict


# Casual praise / benign slang that must NOT be flagged as toxicity.
SAFE_CONTROLS = [
    "개맛있어",          # '개-' intensifier prefix, benign
    "와 진짜 존맛",       # '존맛' = very tasty, benign
    "이거 핵꿀잼",        # '핵-' intensifier, benign
]


@pytest.mark.parametrize("t", SAFE_CONTROLS)
def test_casual_benign_safe(t: str) -> None:
    assert _v(t) is Verdict.SAFE, t


# The colloquial intensifier '존나' (= "really/very") in clearly positive use is exempted
# via a positive-sentiment carve-out (_TOX_INTENSIFIER_OK) so it stays SAFE. Toxic uses of
# '존나' (with insults/attacks) are unaffected — see test_intensifier_toxic_still_flags.
BENIGN_INTENSIFIER = [
    "존나 맛있다",
    "존나 좋아",
    "존나 멋있어",
    "존나 잘한다",
]


@pytest.mark.parametrize("t", BENIGN_INTENSIFIER)
def test_intensifier_benign_safe(t: str) -> None:
    assert _v(t) is Verdict.SAFE, t


# Recall guard: the carve-out must NOT exempt '존나' in toxic/attack contexts.
TOXIC_INTENSIFIER = [
    "존나 머가리 굴려라",
    "존나 사람갖고 노네",
]


@pytest.mark.parametrize("t", TOXIC_INTENSIFIER)
def test_intensifier_toxic_still_flags(t: str) -> None:
    assert _v(t) is not Verdict.SAFE, t
