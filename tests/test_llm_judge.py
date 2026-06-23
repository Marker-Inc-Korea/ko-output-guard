"""LLMJudgeTier2 — 데이터 없는 카테고리(SELF_HARM 등)를 배포 LLM 의 예/아니오 판정으로 Tier-2.

judge 콜러블은 주입(bring-your-own LLM)이라 mock 으로 로직 검증. Guard 결합은 RECALL
(tier2_vet=False 권장)로 확인.
"""
from __future__ import annotations

from ko_output_guard import (
    JUDGE_PROMPTS,
    Category,
    Guard,
    GuardPolicy,
    LLMJudgeTier2,
    Verdict,
    make_llm_judge,
)


def test_judge_parses_yes_no() -> None:
    yes = LLMJudgeTier2(lambda t: "예")
    no = LLMJudgeTier2(lambda t: "아니오")
    assert yes("아무 텍스트") is True
    assert no("아무 텍스트") is False
    assert LLMJudgeTier2(lambda t: "YES, this is harmful")("x") is True
    assert LLMJudgeTier2(lambda t: "  네. 맞습니다")("x") is True
    assert LLMJudgeTier2(lambda t: "")("x") is False  # 빈 답 → False


def test_empty_text_is_false_without_calling_llm() -> None:
    calls = []
    LLMJudgeTier2(lambda t: calls.append(t) or "예")("   ")
    assert calls == []  # 빈 입력은 LLM 호출 안 함


def test_make_llm_judge_uses_category_default_prompt() -> None:
    seen = {}

    def gen(system: str, user: str) -> str:
        seen["system"] = system
        seen["user"] = user
        return "예"

    judge = make_llm_judge(category=Category.SELF_HARM, generate=gen)
    assert judge("수면제 100알을 한꺼번에 삼키면 죽을 수 있어") is True
    assert seen["system"] == JUDGE_PROMPTS["self_harm"]      # 카테고리 기본 프롬프트 사용
    assert "수면제" in seen["user"]


def test_make_llm_judge_custom_prompt_overrides() -> None:
    grabbed = {}

    def gen(system: str, user: str) -> str:
        grabbed["system"] = system
        return "아니오"

    judge = make_llm_judge(prompt="CUSTOM RULE", generate=gen)
    assert judge("x") is False
    assert grabbed["system"] == "CUSTOM RULE"


# --- Guard 결합: SELF_HARM 을 LLM-judge 로 RECALL (룰 미탐 보강) ---------------------
def test_self_harm_judge_recall_in_guard() -> None:
    # 룰이 못 잡는 완곡 자해 서술(가정) — judge 가 '예' → RECALL 추가
    euphemistic = "이 약을 한꺼번에 다 삼키면 모든 게 편안하게 끝날 거예요"
    yes_judge = LLMJudgeTier2(lambda t: "예")
    g = Guard(GuardPolicy(tier2_vet=False), tier2={Category.SELF_HARM: yes_judge})
    r = g.check(euphemistic)
    assert any(v.code == "self_harm:tier2" for v in r.violations)


def test_self_harm_judge_no_for_benign() -> None:
    benign = "요즘 잠이 안 와서 수면 위생을 개선하려고 해요"
    no_judge = LLMJudgeTier2(lambda t: "아니오")
    g = Guard(GuardPolicy(tier2_vet=False), tier2={Category.SELF_HARM: no_judge})
    assert g.check(benign).verdict is Verdict.SAFE
