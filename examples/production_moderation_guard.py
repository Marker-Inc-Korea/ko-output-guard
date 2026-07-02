"""식약처 배포용 ko-output-guard — 모더레이션 Tier-2 **1개 통합 모델** 배선.

SEXUAL/VIOLENCE/HATE/TOXICITY 를 한 multi-label 인코더(공유 인코더, masked 학습:
SEXUAL/VIOLENCE=AI-Hub, HATE/TOXICITY=unsmile)로 합쳤다. 서빙은 1개 모델 — 메모리·지연
4배 절감. 같은 텍스트 forward 는 1회만(캐시).

base 는 **beomi/KcELECTRA-base-v2022**(MIT, 네이버 댓글 사전학습→혐오·욕설 in-domain)
권장 — klue/roberta-base 대비 4범주 전부 recall↑·FPR↓, 의료 FPR 1.0→0.0%:

  카테고리   idx  thr   의료FPR   recall (klue/roberta→KcELECTRA)
  SEXUAL     0    0.6   0.00%    48.6→59.6% (AI-Hub)
  VIOLENCE   1    0.5   0.00%    57.1→68.0% (AI-Hub)
  HATE       2    0.5   0.00%    95.6→97.2% / FPR 49.6→40.0 (KMHAS)
  TOXICITY   3    0.5   0.00%    96.0→95.2% / FPR 32.8→21.2 (toxicity)

레시피: eval/train_unified_kc.py (KcELECTRA, 배포본) · eval/train_unified.py (klue, 기존).
SELF_HARM 은 라벨 데이터가 없어 LLM-judge(배포 LLM). 사용:
  from production_moderation_guard import GUARD ; GUARD.check(llm_output)

분류기 가중치는 레포에 없음(bring-your-own). 환경변수 ``KO_OUT_CLF_DIR`` 로 통합 모델 경로를
지정하면 Tier-2 가 배선되고, 없으면 **룰-only 로 graceful fallback**(코어는 ML-free 유지) —
import 만으로 torch/가중치를 요구하지 않는다.
"""
import os

from ko_output_guard import Guard, GuardPolicy, Category, MultiLabelClassifierTier2

# tier2_vet=False: 분류기는 룰이 못 잡은 콘텐츠만 RECALL 보강(룰 정탐 보존, 요청형 blind 방지).
# base=KcELECTRA 로 학습한 통합 모델 경로(bring-your-own; eval/train_unified_kc.py 산출물).
_CLF_DIR = os.environ.get("KO_OUT_CLF_DIR", "")

if _CLF_DIR and os.path.isdir(_CLF_DIR):
    # lazy backend 아님 주의: MultiLabelClassifierTier2 는 생성 시 torch 로드. isdir 가드로
    # 가중치가 실제 있을 때만 인스턴스화한다.
    _ML = MultiLabelClassifierTier2(_CLF_DIR)  # 1개 모델 공유
    GUARD = Guard(GuardPolicy(tier2_vet=False), tier2={
        Category.SEXUAL:   _ML.for_label(0, threshold=0.6),
        Category.VIOLENCE: _ML.for_label(1, threshold=0.5),
        Category.HATE:     _ML.for_label(2, threshold=0.5),
        Category.TOXICITY: _ML.for_label(3, threshold=0.5),
    })
else:
    # 가중치 미지정/부재 → 룰-only(결정론 Tier-1). README 의 'bring-your-own, 미설치 시
    # 룰-only' 약속과 일치한다.
    GUARD = Guard()

# --- Tier-2 LLM-judge 배선 (SELF_HARM / ILLEGAL / UNSAFE_ADVICE) ---------------------
# KcELECTRA 통합 분류기는 SEXUAL/VIOLENCE/HATE/TOXICITY(어휘·명시 콘텐츠)를 덮는다. 그러나
# self_harm/illegal 처럼 *의미적 유해 컴플라이언스*(슬러 없이 조리있게 유해 방법을 설명하는
# 산문 — 정부 벤치 AssurAI 에서 이 계열 recall 이 낮았다)는 학습 라벨이 없어 LLM-judge 로 보강한다.
# judge 는 룰이 못 잡은 카테고리만 RECALL 경로에서 호출(tier2_vet=False)하며 advisory 다.
# JUDGE_PROMPTS 에 의료 carve-out(LD50·병용금기 경고·예방/신고/뉴스는 '아니오')이 내장돼 있어
# 식약처 benign 의료 출력을 오탐하지 않는다(전용 의료 벤치로 FPR 게이트 후 배포).
#
#   from ko_output_guard import make_llm_judge
#   def gemma_yesno(system: str, user: str) -> str:            # 배포 LLM 래퍼(예/아니오만)
#       return gemma.generate(system=system, user=user, max_tokens=4, temperature=0)
#   for cat in (Category.SELF_HARM, Category.ILLEGAL, Category.UNSAFE_ADVICE):
#       GUARD.tier2[cat] = make_llm_judge(category=cat, generate=gemma_yesno)
#
# 측정(eval/judge_eval.py, gemma-4-26B judge, AssurAI 실셋):
#   illegal   recall 6.8 → 28.5%  (safe FPR 2.3 불변)
#   self_harm recall 13.4 → 42.4% (safe FPR 4.8→5.2)
#   의료 benign FPR 0.5 → 1.5% (+1.0pp) — judge 는 opt-in 이라 미배선 기본 가드는 0.5% 불변.
#   즉 harmful-compliance recall +21~29pp 를 advisory FLAG + 의료 FPR 1pp 비용으로 얻는
#   트레이드오프다. 의료 FPR 0% 가 hard-constraint 면 judge 를 끄거나 임계/프롬프트를 조이라.

if __name__ == "__main__":
    wired = _CLF_DIR and os.path.isdir(_CLF_DIR)
    print(f"통합 분류기: {'배선됨' if wired else '미배선(룰-only)'} — KO_OUT_CLF_DIR={_CLF_DIR or '(미설정)'}\n")
    for t in ["그녀의 벗은 몸을 만지며 격렬하게 성관계를 나눴다",
              "칼로 그의 배를 찔러 피가 솟구쳤고 쓰러졌다",
              "그런 외국인들은 다 게으르고 더러워",
              "아 진짜 존나 짜증나네 꺼져",
              "타이레놀은 하루 4000mg을 넘기지 마세요"]:
        r = GUARD.check(t)
        print(r.verdict.name, sorted({v.category.value for v in r.violations}), "|", t[:28])
