"""Guard: LLM 출력 안전 가드의 진입점.

check() 는 순수 함수다 — 출력 텍스트(+선택적 system-prompt context)를 받아 결정론
detector 를 돌리고 GuardResult 를 반환한다. 네트워크·LLM 호출이 없다. BLOCK 이면
위반 구간을 마스킹한 redacted_text 도 제공해 안전한 fallback 출력을 만들 수 있다.
"""
from __future__ import annotations

from collections.abc import Callable

from . import detectors
from .normalize import normalize_for_detection
from .policy import GuardPolicy
from .result import Category, GuardBlocked, GuardResult, Severity, Verdict, Violation

# 원본 텍스트 기준 offset 을 갖는(=정규화 안 거친) 카테고리만 redact 대상.
# toxicity/unsafe/prompt-leak 은 정규화본 offset 이라 원본에 적용하면 어긋난다.
_ORIGINAL_OFFSET = frozenset({Category.SECRET_LEAK, Category.PII_LEAK})

# OG-6: 위해 카테고리(위험권고/자해/무기)는 정규화본 offset 이라 span 마스킹이 어긋난다.
# 이들이 BLOCK 을 유발하면 원문을 그대로 돌려주면 안 되므로(위해 내용 재노출) 전체를
# 차단 placeholder 로 대체한다.
_DANGEROUS_CATEGORIES = frozenset({
    Category.UNSAFE_ADVICE, Category.SELF_HARM, Category.WEAPONS,
})
_BLOCK_PLACEHOLDER = "[BLOCKED: unsafe content removed]"


def _redact(text: str, violations: tuple[Violation, ...]) -> str:
    raw = sorted(
        (v.start, v.end) for v in violations
        if v.category in _ORIGINAL_OFFSET and v.start is not None and v.end is not None
    )
    if not raw:
        return text
    # 겹치거나 인접한 span 을 병합한다 — SECRET·PII 가 독립 검출돼 구간이 겹칠 때
    # 순차 치환이 서로의 결과를 깨뜨려(후행 바이트 재노출) 마스킹이 손상되는 것을 막는다.
    merged: list[list[int]] = [list(raw[0])]
    for s, e in raw[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out = text
    for s, e in reversed(merged):
        out = out[:s] + "[REDACTED]" + out[e:]
    return out


class Guard:
    """정책에 묶인 재사용 가능한 출력 가드. check() 호출 간 상태 없음."""

    def __init__(
        self,
        policy: GuardPolicy | None = None,
        *,
        tier2: dict[Category, Callable[[str], bool]] | None = None,
    ) -> None:
        self.policy = policy or GuardPolicy()
        # Tier-2 cascade — 카테고리별 분류기(LLM-judge/ML). 결정론이 *못 잡은* 카테고리만
        # 호출해 의미적 회색지대의 recall 을 보강한다(결정론이 잡으면 분류기 생략 → fast-path
        # 유지). 미설정({}) 이면 순수 결정론. 외부 검증에서 드러난 결정론 recall 격차용.
        self.tier2: dict[Category, Callable[[str], bool]] = tier2 or {}

    def check(self, text: str, context: str | None = None) -> GuardResult:
        if not isinstance(text, str):
            raise TypeError(f"check() expects str, got {type(text).__name__}")
        p = self.policy
        # SECRET/PII 는 형식 보존을 위해 원본에서, 한국어 detector 는 난독을 편 정규화본에서.
        norm = normalize_for_detection(text) if p.normalize else text
        violations: list[Violation] = []
        degraded = False
        if p.detect_secret:
            violations += detectors.scan_secrets(text)
        if p.detect_pii:
            violations += detectors.scan_pii_leak(text, strict=p.strict)
            # OG-4: ko-pii 부재로 전체 PII 탐지가 비활성이면 강등 표시(strict 면 위에서 예외).
            if not detectors.pii_backend_available():
                degraded = True
        if p.detect_unsafe_advice:
            violations += detectors.scan_unsafe_advice(norm)
        if p.detect_self_harm:
            violations += detectors.scan_self_harm(norm)
        if p.detect_weapons:
            violations += detectors.scan_weapons(norm)
        if p.detect_toxicity:
            violations += detectors.scan_toxicity(norm)
        if p.detect_prompt_leak:
            violations += detectors.scan_prompt_leak(norm, context)
        if p.detect_sexual:
            violations += detectors.scan_sexual(norm)
        if p.detect_violence:
            violations += detectors.scan_violence(norm)
        if p.detect_hate:
            violations += detectors.scan_hate(norm)
        if p.detect_illegal:
            violations += detectors.scan_illegal(norm)
        if p.detect_data_exfil:
            violations += detectors.scan_data_exfil(text)

        # Tier-2 모델(LLM-judge/ML) — 두 역할을 한 분류기 인터페이스로 수행한다:
        #   (1) VET(정밀): 결정론이 잡았으나 의미적 회색지대(ambiguous=True)인 히트를 confirm/
        #       deny → 모델이 '아니다' 하면 드롭(FP 제거), '맞다' 하면 confirmed(=certain) 처리.
        #   (2) RECALL: 결정론이 *못 잡은* 카테고리를 모델이 보강(기존 동작).
        # certain 히트(SECRET/PII/명백한 위반)는 모델을 호출하지 않는다(fast-path). 카테고리당
        # 모델 1회만 호출(probe 동일)하도록 캐시 — '텍스트에 진짜 {카테고리} 위반이 있는가?'.
        if self.tier2:
            _verdict_cache: dict[Category, bool] = {}

            def _model_says(cat: Category) -> bool:
                if cat not in _verdict_cache:
                    probe = text if cat in (Category.SECRET_LEAK, Category.PII_LEAK) else norm
                    _verdict_cache[cat] = bool(self.tier2[cat](probe))
                return _verdict_cache[cat]

            if p.tier2_vet:
                vetted: list[Violation] = []
                for v in violations:
                    if v.ambiguous and v.category in self.tier2:
                        if _model_says(v.category):
                            vetted.append(v.model_copy(update={"ambiguous": False}))  # confirmed→certain
                        # else: 모델이 부정 → 드롭(FP 제거)
                    else:
                        vetted.append(v)
                violations = vetted
            # tier2_vet=False: 룰 히트는 그대로 두고(분류기가 잘못 기각 못 하게) RECALL 만.

            covered = {v.category for v in violations}
            for cat in self.tier2:
                if cat in covered:
                    continue  # 이미 (확인된) 결정론 히트가 있음 → recall 호출 불필요
                if _model_says(cat):
                    violations.append(Violation(
                        code=f"{cat.value}:tier2",
                        category=cat,
                        severity=Severity.MEDIUM,
                        reason="Tier-2 classifier flagged (deterministic was SAFE)",
                    ))

        def _can_block(v: Violation) -> bool:
            if v.severity < p.min_block_severity or v.category not in p.block_categories:
                return False
            # 모델 미확인 ambiguous 는 정밀-우선 모드에서 BLOCK 하지 않고 FLAG 로 둔다.
            if v.ambiguous and not p.block_unconfirmed_ambiguous:
                return False
            return True

        blocking = [v for v in violations if _can_block(v)]
        if blocking:
            verdict = Verdict.BLOCK
        elif violations:
            verdict = Verdict.FLAG
        else:
            verdict = Verdict.SAFE

        vt = tuple(violations)
        redacted = None
        if verdict is Verdict.BLOCK:
            # OG-6: 위해 카테고리가 BLOCK 사유면 span 마스킹(정규화 offset)로는 원문이
            # 그대로 새므로 전체를 차단 placeholder 로 대체한다. SECRET/PII 만 BLOCK 이면
            # 기존 span 마스킹을 유지한다(형식 보존).
            if any(v.category in _DANGEROUS_CATEGORIES for v in blocking):
                redacted = _BLOCK_PLACEHOLDER
            else:
                redacted = _redact(text, vt)
        return GuardResult(
            verdict=verdict, original_text=text, violations=vt, redacted_text=redacted,
            degraded=degraded,
        )

    def enforce(self, text: str, context: str | None = None) -> str:
        """SAFE/FLAG 면 원본 반환, BLOCK 이면 GuardBlocked 발생(redacted 는 결과에)."""
        r = self.check(text, context)
        if r.verdict is Verdict.BLOCK:
            raise GuardBlocked(r)
        return text


def check(text: str, context: str | None = None, policy: GuardPolicy | None = None) -> GuardResult:
    """모듈 레벨 편의 함수 — Guard(policy).check(text, context)."""
    return Guard(policy).check(text, context)
