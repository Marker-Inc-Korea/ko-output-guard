"""결과 타입 — Verdict / Category / Severity / Violation / GuardResult.

ko-prompt-guard 와 동일한 모양(결정론·pydantic·frozen)을 따른다. 출력 가드는
입력 가드의 대칭이므로 API 표면을 일부러 닮게 유지한다.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class Verdict(str, Enum):
    SAFE = "safe"      # 내보내도 안전
    FLAG = "flag"      # 의심 — 사람 검토/로깅 권고
    BLOCK = "block"    # 명백 — 내보내기 차단


class Category(str, Enum):
    RESOURCE_LIMIT = "resource_limit"  # configured text/context work budget exceeded
    SECRET_LEAK = "secret_leak"      # API key/토큰/private key 등 크리덴셜
    PII_LEAK = "pii_leak"            # 개인정보 재누출(ko-pii 연동)
    UNSAFE_ADVICE = "unsafe_advice"  # 식약처 도메인 위험 권고
    SELF_HARM = "self_harm"          # 자해/자살 방법 안내
    WEAPONS = "weapons"              # 무기/폭발물 제조 안내
    TOXICITY = "toxicity"            # 욕설/혐오/유해 표현
    PROMPT_LEAK = "prompt_leak"      # 시스템 프롬프트/지침 그대로 출력
    SEXUAL = "sexual"                # 노골적 성행위·성적 알선 (미성년 시 CSAM)
    VIOLENCE = "violence"            # 살해·폭행 위협/조장, 유혈·잔혹 묘사
    HATE = "hate"                    # 보호집단 비인간화·차별 선동·괴롭힘
    ILLEGAL = "illegal"              # 해킹·피싱·사기·마약·절도 등 범죄 조장
    DATA_EXFIL = "data_exfil"        # 마크다운/HTML 이미지·링크로 외부 URL 데이터 유출


class Severity(int, Enum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.value < other.value
        return NotImplemented


class Violation(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    category: Category
    severity: Severity
    reason: str
    start: int | None = None
    end: int | None = None
    matched: str | None = None
    # 결정론 룰이 *확실*하게 잡았는지(certain), 의미적 회색지대라 모델 확인이 바람직한지
    # (ambiguous). substring/형식(secret/pii/word-boundary)은 certain, 콘텐츠 모더레이션
    # (use-vs-mention)·도메인 권고(advice-vs-warning)처럼 룰이 의미를 흉내내는 카브아웃에
    # 의존하는 히트는 ambiguous=True 로 둔다. Guard 가 Tier-2 모델로 confirm/deny 한다.
    # 모델이 없으면 기본은 무동작(메타데이터) — block_unconfirmed_ambiguous=False 면 FLAG 강등.
    ambiguous: bool = False


class SafeViolationTelemetry(BaseModel):
    """A violation summary that cannot carry source text or detector matches."""

    model_config = ConfigDict(frozen=True)

    code: str
    category: Category
    severity: Severity


class SafeTelemetry(BaseModel):
    """Safe-to-log decision data with no original output, match, or reason fields."""

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    forward_safe: bool
    degraded: bool
    violations: tuple[SafeViolationTelemetry, ...] = ()


class GuardResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    original_text: str
    violations: tuple[Violation, ...] = ()
    # 가장 안전한 출력형: BLOCK 사유를 마스킹한 텍스트(없으면 None).
    redacted_text: str | None = None
    # OG-4: PII 백엔드(ko-pii) 미설치 등으로 일부 탐지가 비활성된 '강등' 상태인지.
    # True 면 PII 누출 탐지가 부분적으로만(부분 RRN 정규식 등) 동작했음을 호출자에 알린다.
    degraded: bool = False

    @property
    def is_safe(self) -> bool:
        return self.forward_safe

    @property
    def forward_safe(self) -> bool:
        """Whether the original text is safe to forward to an end user."""
        return self.verdict is Verdict.SAFE and not self.degraded

    @property
    def safe_text(self) -> str:
        """The only output text safe to forward for this decision."""
        if self.forward_safe:
            return self.original_text
        if self.redacted_text is not None:
            return self.redacted_text
        return "[BLOCKED: output requires review]"

    def to_safe_telemetry(self) -> SafeTelemetry:
        """Return a log-safe DTO that intentionally excludes source text and matches."""
        return SafeTelemetry(
            verdict=self.verdict,
            forward_safe=self.forward_safe,
            degraded=self.degraded,
            violations=tuple(
                SafeViolationTelemetry(
                    code=violation.code,
                    category=violation.category,
                    severity=violation.severity,
                )
                for violation in self.violations
            ),
        )


class GuardBlocked(Exception):
    """enforce() 가 forward-safe 하지 않은 출력에 대해 발생시키는 예외."""

    def __init__(self, result: GuardResult) -> None:
        self.result = result
        cats = ", ".join(sorted({v.category.value for v in result.violations}))
        detail = cats or "degraded guard result"
        super().__init__(f"output blocked: {detail}")
