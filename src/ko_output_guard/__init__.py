"""ko-output-guard — 결정론 한국어 LLM 출력 안전 가드.

입력 가드(ko-prompt-guard)의 대칭. LLM 출력에서 크리덴셜/PII 누출, 식약처 도메인
위험 권고, 유해 표현, 시스템 프롬프트 누출을 잡는다. 순수·결정론(네트워크/LLM 없음).

    from ko_output_guard import Guard
    r = Guard().check(llm_output, context=system_prompt)
    if r.verdict is not Verdict.SAFE:
        ...  # r.violations, r.redacted_text
"""
from __future__ import annotations

from .detectors import PIIBackendUnavailable, pii_backend_available
from .guard import Guard, check
from .policy import GuardPolicy
from .result import Category, GuardBlocked, GuardResult, Severity, Verdict, Violation

# Opt-in Tier-2 reviewer (ML-free at import; bge-m3 backend imported lazily).
from .reviewers import (
    JUDGE_PROMPTS,
    CascadeTier2,
    ClassifierTier2,
    EmbeddingTier2,
    LLMJudgeTier2,
    MultiLabelClassifierTier2,
    default_hate_anchors,
    make_bge_encoder,
    make_harmful_cascade,
    make_harmful_tier2,
    make_hate_tier2,
    make_llm_judge,
    make_openai_judge_generate,
)

__version__ = "0.2.0"
__all__ = [
    "Guard", "check", "GuardPolicy", "GuardResult", "GuardBlocked",
    "Verdict", "Category", "Severity", "Violation",
    "PIIBackendUnavailable", "pii_backend_available",
    "EmbeddingTier2", "ClassifierTier2", "MultiLabelClassifierTier2",
    "LLMJudgeTier2", "CascadeTier2",
    "make_hate_tier2", "make_harmful_tier2", "make_harmful_cascade",
    "make_llm_judge", "make_openai_judge_generate", "make_bge_encoder",
    "default_hate_anchors", "JUDGE_PROMPTS",
]
