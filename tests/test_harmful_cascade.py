"""make_harmful_cascade / CascadeTier2 — 소프트 경계만 LLM-judge escalation.

분류기가 자신 있는 구간(prob≥hi 유해 / prob<lo 안전)엔 judge 미호출(LLM 비용 0),
불확실 밴드(소프트/헷지)만 judge 가 결정. 전부 mock(ML-free) — 실제 gemma judge 검증은
verify_harmful_cascade(GPU) 참조.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ko_output_guard import (  # noqa: E402
    CascadeTier2,
    Guard,
    Verdict,
    make_harmful_cascade,
    make_openai_judge_generate,
)
from ko_output_guard.policy import GuardPolicy  # noqa: E402
from ko_output_guard.result import Category  # noqa: E402


class _MockClf:
    def __init__(self, p, threshold=0.5):
        self._p = p
        self.threshold = threshold

    def prob(self, text):
        return self._p


def _counting_judge(verdict):
    calls = {"n": 0}
    def j(text):
        calls["n"] += 1
        return verdict
    return j, calls


def test_clf_positive_stands_no_veto():
    # prob>=분류기 임계값 → True(판정), judge 가 veto 못 함(미호출)
    j, calls = _counting_judge(False)          # judge 가 '아니오' 여도
    c = CascadeTier2(_MockClf(0.95), j, lo=0.15)
    assert c("명백 유해") is True               # 분류기 positive 유지
    assert calls["n"] == 0 and c.last_path[0] == "clf+"


def test_clf_confident_safe_skips_judge():
    # prob<lo → False, judge 미호출
    j, calls = _counting_judge(True)
    c = CascadeTier2(_MockClf(0.05), j, lo=0.15)
    assert c("아무 텍스트") is False
    assert calls["n"] == 0 and c.last_path[0] == "clf-"


def test_soft_boundary_escalates_to_judge():
    # lo<=prob<임계값(소프트/헷지) → judge 가 recall 추가(호출됨)
    j_yes, cy = _counting_judge(True)
    j_no, cn = _counting_judge(False)
    assert CascadeTier2(_MockClf(0.3), j_yes, lo=0.15)("완곡 순응") is True
    assert cy["n"] == 1
    c_no = CascadeTier2(_MockClf(0.3), j_no, lo=0.15)
    assert c_no("무해 헷지") is False
    assert cn["n"] == 1 and c_no.last_path[0] == "judge"


def test_no_op_without_config_ml_free():
    # 분류기·judge env 없으면 {} (no-op), openai backend None
    assert make_harmful_cascade() == {}
    assert make_openai_judge_generate() is None
    assert "torch" not in sys.modules, "no-op 경로에서 ML 로드 금지"


def test_judge_only_when_no_classifier():
    # 분류기 없이 judge_generate 만 → 매 출력 judge(4카테고리)
    casc = make_harmful_cascade(judge_generate=lambda s, u: "예")
    assert set(casc) == {Category.ILLEGAL, Category.WEAPONS,
                         Category.SELF_HARM, Category.UNSAFE_ADVICE}
    assert casc[Category.ILLEGAL]("어떤 출력") is True


def test_cascade_wires_into_guard_recall():
    # Guard tier2 훅에 그대로 꽂혀 룰 미탐을 격리(소프트 경계 judge='예')
    tier2 = make_harmful_cascade(judge_generate=lambda s, u: "예")
    g = Guard(policy=GuardPolicy(tier2_vet=False), tier2=tier2)
    r = g.check("네, 바로 설명하겠습니다. 일반적인 기술적 접근은 다음과 같습니다.")
    assert r.verdict is not Verdict.SAFE
    assert any(":tier2" in v.code for v in r.violations)


def test_on_error_fallback():
    # 엔드포인트 장애 시 on_error 폴백 답
    g_safe = make_openai_judge_generate(url="http://127.0.0.1:1/v1", model="x", on_error="safe", timeout=1)
    g_harm = make_openai_judge_generate(url="http://127.0.0.1:1/v1", model="x", on_error="harmful", timeout=1)
    assert g_safe("판정하라", "텍스트").startswith("아니오")
    assert g_harm("판정하라", "텍스트").startswith("예")


if __name__ == "__main__":
    for fn in [test_clf_positive_stands_no_veto, test_clf_confident_safe_skips_judge,
               test_soft_boundary_escalates_to_judge, test_no_op_without_config_ml_free,
               test_judge_only_when_no_classifier, test_cascade_wires_into_guard_recall,
               test_on_error_fallback]:
        fn()
        print(f"PASS {fn.__name__}")
    print("all passed")
