"""식약처 배포용 ko-output-guard — 모더레이션 Tier-2 **1개 통합 모델** 배선.

SEXUAL/VIOLENCE/HATE/TOXICITY 를 한 multi-label klue/roberta(공유 인코더, masked 학습:
SEXUAL/VIOLENCE=AI-Hub, HATE/TOXICITY=unsmile)로 합쳤다. per-category 성능이 분리 4모델과
동등하면서(아래) 서빙은 1개 모델 — 메모리·지연 4배 절감. 같은 텍스트 forward 는 1회만(캐시).

  카테고리   idx  thr   의료FPR   held-out recall(분리모델)
  SEXUAL     0    0.6   0.60%    48.6%(50.3)
  VIOLENCE   1    0.5   0.00%    57.1%(59.7)
  HATE       2    0.5   0.53%    89.8%unsmile/62.4%KMHAS (90.8/56.8)
  TOXICITY   3    0.5   0.00%    91.9%(91.6)

SELF_HARM 은 라벨 데이터가 없어 LLM-judge(배포 LLM). 사용:
  from production_moderation_guard import GUARD ; GUARD.check(llm_output)
"""
from ko_output_guard import Guard, GuardPolicy, Category, MultiLabelClassifierTier2

# tier2_vet=False: 분류기는 룰이 못 잡은 콘텐츠만 RECALL 보강(룰 정탐 보존, 요청형 blind 방지).
_ML = MultiLabelClassifierTier2("/data1/mk04/eval_external/unified_model/final")  # 1개 모델 공유
GUARD = Guard(GuardPolicy(tier2_vet=False), tier2={
    Category.SEXUAL:   _ML.for_label(0, threshold=0.6),
    Category.VIOLENCE: _ML.for_label(1, threshold=0.5),
    Category.HATE:     _ML.for_label(2, threshold=0.5),
    Category.TOXICITY: _ML.for_label(3, threshold=0.5),
})

# SELF_HARM 은 학습 데이터가 없어 LLM-judge(배포 LLM=Gemma/Solar 주입):
# from ko_output_guard import make_llm_judge
# def gemma_yesno(system, user):
#     return gemma.generate(system=system, user=user, max_tokens=4, temperature=0)
# GUARD.tier2[Category.SELF_HARM] = make_llm_judge(category=Category.SELF_HARM, generate=gemma_yesno)

if __name__ == "__main__":
    for t in ["그녀의 벗은 몸을 만지며 격렬하게 성관계를 나눴다",
              "칼로 그의 배를 찔러 피가 솟구쳤고 쓰러졌다",
              "그런 외국인들은 다 게으르고 더러워",
              "아 진짜 존나 짜증나네 꺼져",
              "타이레놀은 하루 4000mg을 넘기지 마세요"]:
        r = GUARD.check(t)
        print(r.verdict.name, sorted({v.category.value for v in r.violations}), "|", t[:28])
