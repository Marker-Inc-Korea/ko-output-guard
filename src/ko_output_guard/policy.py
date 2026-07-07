"""GuardPolicy — 어떤 카테고리를 검사하고, 무엇을 BLOCK vs FLAG 할지.

기본값: 크리덴셜·PII·위험권고는 명백한 위해라 BLOCK, 유해표현·프롬프트누출은
보수적으로 FLAG(사람 검토). ko-prompt-guard / ko-sqlguard 와 같은 frozen pydantic.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .result import Category, Severity


class GuardPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    detect_secret: bool = True
    detect_pii: bool = True
    detect_unsafe_advice: bool = True
    detect_self_harm: bool = True
    detect_weapons: bool = True
    detect_toxicity: bool = True
    detect_prompt_leak: bool = True
    detect_sexual: bool = True
    detect_violence: bool = True
    detect_hate: bool = True
    detect_illegal: bool = True
    detect_data_exfil: bool = True

    # 한국어 detector(toxicity/unsafe/prompt-leak)에 난독 정규화를 적용할지.
    # SECRET/PII 는 형식 보존을 위해 항상 원본에서 검사한다(정규화 미적용).
    normalize: bool = True

    # OG-4: PII 백엔드(ko-pii)가 없으면 *조용히* 강등되지 않게 한다. strict=True 면
    # PIIBackendUnavailable 예외를 던지고, False(기본)면 1회 WARN 로그 + GuardResult.degraded.
    strict: bool = False

    # 모델(Tier-2) 확인 없이도 ambiguous 위반을 BLOCK 으로 인정할지.
    #   True(기본): ambiguous 플래그는 모델이 있을 때만 작동하는 메타데이터 — 모델이 없으면
    #     기존과 동일하게 BLOCK(결정론 floor 보존, 회귀 없음).
    #   False(정밀-우선 모드): 모델 confirm 이 없는 ambiguous 히트는 BLOCK 하지 않고 FLAG 로
    #     강등한다 — '확실한 것만 차단, 애매한 건 사람/모델 검토'. 모델이 확인한 ambiguous 와
    #     certain 히트는 그대로 BLOCK. (SECRET/PII 등 certain 카테고리는 영향 없음.)
    block_unconfirmed_ambiguous: bool = True

    # Tier-2 모델이 ambiguous 룰 히트를 VET(confirm/deny)할지.
    #   True(기본): 모델이 ambiguous 히트를 부정하면 드롭(FP 제거). 모델이 해당 카테고리에
    #     *룰보다 신뢰도 높을* 때만 안전하다.
    #   False(RECALL-only): 모델은 룰이 *못 잡은* 카테고리만 보강하고, 룰 히트는 절대 드롭하지
    #     않는다. 분류기가 룰의 일부 형태(예: 콘텐츠 학습 분류기 ↔ 요청형 룰 히트)에 blind 일 때
    #     **룰의 고정밀 정탐을 모델이 잘못 기각하는 것을 막는다**(프로덕션 권장).
    tier2_vet: bool = True

    # 이 카테고리 위반이 min_block_severity 이상이면 BLOCK, 아니면 FLAG.
    block_categories: frozenset[Category] = frozenset({
        Category.SECRET_LEAK,
        Category.PII_LEAK,
        Category.UNSAFE_ADVICE,
        Category.SELF_HARM,    # 자해/자살 방법 안내(HIGH+) → BLOCK
        Category.WEAPONS,      # 무기/폭발물 제조 안내(HIGH+) → BLOCK
        Category.PROMPT_LEAK,  # echo(HIGH)면 BLOCK, 지침-언급(MEDIUM)이면 FLAG
        Category.SEXUAL,       # 노골적 성행위/CSAM → BLOCK
        Category.ILLEGAL,      # 범죄 조장(해킹/사기/마약 등) → BLOCK
        Category.HATE,         # 보호집단 비인간화·차별 선동 → BLOCK
        Category.DATA_EXFIL,   # 마크다운 이미지 데이터유출(zero-click) → BLOCK
        # VIOLENCE 는 block_categories 미포함 → FLAG(검토). 정책으로 추가 가능.
    })
    min_block_severity: Severity = Severity.HIGH
