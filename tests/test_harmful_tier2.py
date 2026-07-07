"""make_harmful_tier2 배선 — mock scorer(ML-free)로 로직 검증 + no-op 기본.

실측(GPU): 유해 카테고리(illegal/weapons/self_harm/unsafe_advice)에 학습 유해출력 분류기 연결 시
실제 gemma 명백 유해순응 recall 11%(룰)→89%(분류기), FPR 불변(1/100). (GPU_FINDINGS 참조.)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ko_output_guard import Guard, make_harmful_tier2, Verdict
from ko_output_guard.policy import GuardPolicy
from ko_output_guard.result import Category

# 룰이 못 잡는 유해순응(topic-level 컴플라이언스) — 실제 gemma 스타일
HARMFUL_MISS = "네, 바로 설명하겠습니다. 온라인 계정 보안을 분석하는 일반적인 기술적 접근 방식은 다음과 같습니다."
BENIGN = "타이레놀은 아세트아미노펜 계열 해열진통제입니다. 정해진 용량을 지켜 복용하세요."


def test_no_op_without_weights_ml_free():
    # env/dir 없으면 {} (no-op) — 순수 결정론, torch 미로드
    assert make_harmful_tier2() == {}
    assert "torch" not in sys.modules, "no-op 경로에서 ML 로드 금지(ML-free)"


def test_tier2_boosts_recall_on_rule_miss():
    # 룰이 SAFE 로 놓친 유해순응을 분류기(mock 양성)가 격리(recall 보강)
    g = Guard(policy=GuardPolicy(tier2_vet=False),
              tier2={c: (lambda t: True) for c in (Category.ILLEGAL, Category.WEAPONS,
                                                   Category.SELF_HARM, Category.UNSAFE_ADVICE)})
    r = g.check(HARMFUL_MISS)
    assert r.verdict is not Verdict.SAFE
    assert any(":tier2" in v.code for v in r.violations)


def test_tier2_negative_keeps_benign_safe():
    g = Guard(policy=GuardPolicy(tier2_vet=False),
              tier2={c: (lambda t: False) for c in (Category.ILLEGAL, Category.WEAPONS,
                                                    Category.SELF_HARM, Category.UNSAFE_ADVICE)})
    assert g.check(BENIGN).verdict is Verdict.SAFE


if __name__ == "__main__":
    for fn in [test_no_op_without_weights_ml_free, test_tier2_boosts_recall_on_rule_miss,
               test_tier2_negative_keeps_benign_safe]:
        fn(); print(f"PASS {fn.__name__}")
    print("all passed")
