"""Tier-2 '애매 → 모델' 에스컬레이션 — 결정론 룰은 확실한 것만 차단하고, 의미적
회색지대(ambiguous)는 모델이 confirm/deny 한다.

설계: 콘텐츠 모더레이션(use-vs-mention)·도메인 권고(advice-vs-warning)는 룰이 의미를
흉내내는 카브아웃에 의존하므로 ambiguous=True. format 카테고리(SECRET/PII)와 명시적
위험 지시는 certain. Guard(tier2={cat: fn}) 의 fn 은 두 역할:
  - VET(정밀): ambiguous 히트 confirm/deny — deny 면 드롭(FP 제거)
  - RECALL: 결정론이 못 잡은 카테고리 보강
모델이 없으면 기본은 무동작(회귀 0). block_unconfirmed_ambiguous=False 면 정밀-우선
(애매는 FLAG, 확실만 BLOCK).
"""
from __future__ import annotations

from ko_output_guard import Category, Guard, GuardPolicy, Verdict

# 콘텐츠 카테고리(ambiguous) 단독 — 잔여 certain 위반이 섞이지 않게 깔끔한 예시 사용.
HATE = "장애인은 사회에서 박멸해야 한다"          # hate seed (ambiguous)
SECRET = ("배포 키: " + "AKIA" + "IOSFODNN7EXAMPLE / "
          "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")  # secret (certain)
DUR = "로수바스타틴과 사이클로스포린을 같이 드시면 효과가 두 배예요"  # dur_interaction (ambiguous)
TOXIC_INGEST = "독소를 빼려면 매일 아침 표백제를 희석해서 드세요"     # toxic_ingestion (certain)


def _yes(_s: str) -> bool:
    return True


def _no(_s: str) -> bool:
    return False


# --- (1) 모델 없음 → 회귀 없음(ambiguous 는 무동작 메타데이터) ----------------------
def test_no_model_no_regression() -> None:
    g = Guard()
    assert g.check(HATE).verdict is Verdict.BLOCK      # ambiguous 여도 기본은 BLOCK
    assert g.check(SECRET).verdict is Verdict.BLOCK
    assert g.check(DUR).verdict is Verdict.BLOCK


def test_ambiguous_flag_is_set_on_content_and_dur() -> None:
    hate_v = [v for v in Guard().check(HATE).violations if v.category is Category.HATE]
    assert hate_v and all(v.ambiguous for v in hate_v)
    dur_v = [v for v in Guard().check(DUR).violations if v.code == "dur_interaction"]
    assert dur_v and all(v.ambiguous for v in dur_v)


def test_certain_flag_on_secret_and_toxic_ingestion() -> None:
    sec = [v for v in Guard().check(SECRET).violations if v.category is Category.SECRET_LEAK]
    assert sec and not any(v.ambiguous for v in sec)
    ti = [v for v in Guard().check(TOXIC_INGEST).violations if v.code == "toxic_ingestion"]
    assert ti and not any(v.ambiguous for v in ti)


# --- (2) 모델 VET: ambiguous 히트를 deny → 드롭(FP 제거) ----------------------------
def test_model_deny_drops_ambiguous_hit() -> None:
    g = Guard(tier2={Category.HATE: _no})
    r = g.check(HATE)
    assert not any(v.category is Category.HATE for v in r.violations)  # 모델이 부정 → 드롭
    assert r.verdict is Verdict.SAFE


def test_model_deny_drops_ambiguous_dur() -> None:
    g = Guard(tier2={Category.UNSAFE_ADVICE: _no})
    r = g.check(DUR)
    assert r.verdict is Verdict.SAFE


# --- (3) 모델 confirm: ambiguous 히트 유지 → BLOCK ----------------------------------
def test_model_confirm_keeps_ambiguous_hit() -> None:
    g = Guard(tier2={Category.HATE: _yes})
    assert g.check(HATE).verdict is Verdict.BLOCK


# --- (4) certain 은 모델이 deny 해도 영향 없음(format 은 vet 대상 아님) ----------------
def test_certain_not_vetted_even_with_model() -> None:
    g = Guard(tier2={Category.SECRET_LEAK: _no})  # 모델이 deny 해도
    assert g.check(SECRET).verdict is Verdict.BLOCK  # certain 이라 드롭 안 됨


def test_certain_skips_model_call() -> None:
    calls: list[str] = []

    def spy(s: str) -> bool:
        calls.append(s)
        return False

    Guard(tier2={Category.SECRET_LEAK: spy}).check(SECRET)
    assert calls == []  # certain 히트는 모델 호출 안 함(fast-path)


# --- (5) RECALL: 결정론이 못 잡은 카테고리를 모델이 보강 -----------------------------
def test_model_recall_on_empty_category() -> None:
    g = Guard(tier2={Category.TOXICITY: _yes})
    r = g.check("아주 평범하고 안전한 안내 문장입니다")
    assert any(v.code == "toxicity:tier2" for v in r.violations)


# --- (6) 정밀-우선 모드(모델 없음): 확실만 BLOCK, 애매는 FLAG --------------------------
def test_precision_first_downgrades_unconfirmed_ambiguous() -> None:
    g = Guard(GuardPolicy(block_unconfirmed_ambiguous=False))
    assert g.check(HATE).verdict is Verdict.FLAG       # ambiguous → FLAG
    assert g.check(DUR).verdict is Verdict.FLAG        # ambiguous → FLAG
    assert g.check(SECRET).verdict is Verdict.BLOCK    # certain → BLOCK
    assert g.check(TOXIC_INGEST).verdict is Verdict.BLOCK  # certain → BLOCK


# --- (7) 정밀-우선 + 모델 confirm → BLOCK 복귀 -------------------------------------
def test_precision_first_with_model_confirm_blocks() -> None:
    g = Guard(GuardPolicy(block_unconfirmed_ambiguous=False),
              tier2={Category.HATE: _yes})
    assert g.check(HATE).verdict is Verdict.BLOCK  # 모델 confirm → certain 화 → BLOCK


# --- (8) tier2_vet=False: 분류기는 룰 히트를 드롭하지 않고 RECALL 만 -------------------
def test_tier2_vet_false_keeps_rule_hit_on_deny() -> None:
    # vet=True(기본): 모델 deny → ambiguous hate 드롭 → SAFE
    assert Guard(tier2={Category.HATE: _no}).check(HATE).verdict is Verdict.SAFE
    # vet=False: 분류기가 deny 해도 룰 히트 보존 → BLOCK
    g = Guard(GuardPolicy(tier2_vet=False), tier2={Category.HATE: _no})
    assert g.check(HATE).verdict is Verdict.BLOCK


def test_tier2_vet_false_still_does_recall() -> None:
    g = Guard(GuardPolicy(tier2_vet=False), tier2={Category.TOXICITY: _yes})
    r = g.check("아주 평범하고 안전한 안내 문장입니다")
    assert any(v.code == "toxicity:tier2" for v in r.violations)  # RECALL 은 그대로
