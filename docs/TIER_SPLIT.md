# Tier-1(룰) / Tier-2(모델) 경계 — 무엇을 결정론으로, 무엇을 모델로

원칙: **결정론 룰은 *확실한 것*만 잡는다. 의미가 걸린 회색지대는 모델이 판단한다.**
룰로 의미 판단을 흉내내는 카브아웃을 쌓으면 brittle(새 표현 누락·과억제)해진다.

## 1. 카브아웃/휴리스틱 전수 감사

각 detector 의 보정 로직을 두 종류로 나눈다.

### A. 버그픽스 / 형식 (→ 결정론 유지, `ambiguous=False` = certain)
의미가 아니라 *토큰화/형식* 문제. 룰이 정답이며 모델이 필요 없다.

| 위치 | 내용 | 왜 certain |
|---|---|---|
| toxicity `_TOX_MED_WHITELIST` | 시바⊂트레**시바**, 존나⊂페라**존나**트륨 lookaround | 약품명 substring 충돌 = 버그 |
| weapons `(?<![가-힣])리신`·`(?<!메)독소` | 리신⊂알**리신**, 독소⊂메**독소**밀 | 단어경계 버그 |
| hate `(?<![가-힣])니거`·`메갈(?!로)` | 니거⊂아**니거**나, 메갈⊂시토**메갈**로 | substring 버그 |
| violence `화형(?:에\|시키…)` | 화형⊂친**화형** | substring 버그 |
| sexual: bare `체위`/`삽입` 제거, CSAM `애`/`소아`/`성기` 수정 | 體位성, 스텐트, 급**성기** | 잘못된 seed/패턴 |
| self_harm `정맥` anchor 제거, `째(?:고\|서…)` | 정맥주사, 1,2,3일**째** | 형식 충돌 |
| pii `_EXCLUDE`(IP/WEIGHT/…), 대표번호 필터 | 버전번호·임상수치·공개번호 | 비식별/구조화 = 형식 |
| secret 벤더 형식 패턴 | AWS/JWT/PEM 형식 | 형식 = 결정적 |

→ 이 부류는 이번/이전 커밋에서 **단어경계·lookaround·라벨제외**로 고정했다. 모델 영역 아님.

### B. 의미적 휴리스틱 (→ 모델 후보, `ambiguous=True`)
룰이 *use-vs-mention / advice-vs-warning / intent* 를 정규식으로 근사. 모델이 더 정확.

| 위치 | 의미 판단 | 현재 룰 근사 |
|---|---|---|
| sexual/violence/hate/illegal `_CARVEOUT` | 슬러 *사용* vs 인용/뉴스/교육/인권옹호 *언급* | 키워드 carve-out |
| unsafe_advice `_has_genuine_warning`·`_WARNING_STRUCTURE` | 위험 *지시* vs *경고/만류* | 금지·만류 동사 구조 |
| unsafe_advice `_DUR_CONTRA` + DUR | 병용 *권장* vs 병용금기 *정보* | 권고동사+금기문맥부재 |
| unsafe_advice `_FALSE_CURE_DEBUNK` | 가짜치료 *주장* vs *반박* | debunk 키워드 |
| self_harm `_is_protective`·`_DISCOURAGE` | 자해 *조장* vs *위기개입* | 만류 동사 |
| self_harm 치사량 게이팅 | LD50 *과학* vs *자살용량* | 사람-섭취 동사 근접 |
| toxicity `_TOX_INTENSIFIER_OK` | `존나` *칭찬강조* vs *공격* | 긍정형용사 lookahead |

## 2. 결정 — 모델은 어디에 들어가나

**콘텐츠/도메인 7범주에 모델(Tier-2)을 둔다. 형식 2범주는 결정론으로 둔다.**

- 모델 vet 대상(ambiguous 가능): `SEXUAL · VIOLENCE · HATE · ILLEGAL · UNSAFE_ADVICE · SELF_HARM · TOXICITY`
- 결정론 전담(항상 certain): `SECRET_LEAK · PII_LEAK` — 형식이 결정적이라 의미 판단 불필요(AWS 키는 그냥 키다)
- `PROMPT_LEAK` — 구조적(context-echo)이 주라 일단 결정론. 1인칭-표지 부분은 향후 ambiguous 후보.

현재 코드에서 `ambiguous=True` 로 표시한 것(프로토타입 범위): 콘텐츠 4범주(sexual/violence/hate/illegal) 전체 + unsafe_advice 의 `dur_interaction`·`dur_pregnancy`·`dur_age`·`false_cure`. 나머지(toxicity intensifier, self_harm protective)는 같은 패턴으로 확장 가능(detector 에서 해당 히트에 `ambiguous=True` 부여).

## 3. 메커니즘 — `ambiguous` 플래그 + Tier-2 confirm/deny

```
결정론 히트 → certain  → 항상 적용(모델 호출 안 함, fast-path)
            → ambiguous → 모델 있으면 confirm/deny:
                            deny → 드롭(FP 제거)
                            confirm → 유지(certain 화)
                          모델 없으면:
                            block_unconfirmed_ambiguous=True(기본) → 기존대로 BLOCK(회귀 0)
                            block_unconfirmed_ambiguous=False      → FLAG(정밀-우선)
결정론 미히트 카테고리 → 모델 있으면 recall 보강(기존 동작)
```

세 가지 배포 모드:
1. **순수 결정론**(`Guard()`): 모델 0개. ambiguous 는 무동작 메타데이터 → 기존과 동일.
2. **정밀-우선 결정론**(`Guard(GuardPolicy(block_unconfirmed_ambiguous=False))`): 모델 없이도
   "확실만 BLOCK, 애매는 FLAG(사람 검토)". 자동 차단의 FP 를 0 에 가깝게.
3. **모델 보강**(`Guard(tier2={cat: fn})`): 애매한 히트를 모델이 vet(FP↓) + 미탐 보강(recall↑).

## 4. 레퍼런스 confirmer (식약처 Gemma 등 인하우스 LLM 배선)

`tier2` 값은 `(str) -> bool` — "이 텍스트에 진짜 {카테고리} 위반이 있는가?". 카테고리당 1회
호출(가드가 캐시). 패키지는 인터페이스만 제공하고 모델은 bring-your-own.

```python
from ko_output_guard import Guard, Category

_PROMPTS = {
    Category.HATE: "다음 텍스트가 보호집단(인종·성별·장애·성소수자 등)을 향한 실제 혐오·비하·"
                   "차별 선동인가? 단순 인용·뉴스보도·교육·반대(인권옹호)면 아니다.",
    Category.UNSAFE_ADVICE: "다음 텍스트가 위험한 약물/식품 사용을 *권장*하는가? 병용금기·상호"
                            "작용을 *경고/설명*하거나 하지 말라고 만류하면 아니다.",
    Category.SELF_HARM: "다음 텍스트가 자해/자살 *방법을 안내·조장*하는가? 위기개입·예방·"
                        "약리(LD50) 설명이면 아니다.",
    # SEXUAL / VIOLENCE / ILLEGAL / TOXICITY 도 동일 패턴.
}

def make_confirmer(category, llm):
    sys = _PROMPTS[category] + " 반드시 'YES' 또는 'NO' 한 단어로만 답하라."
    def confirm(text: str) -> bool:
        ans = llm.generate(system=sys, user=text, max_tokens=3, temperature=0)
        return ans.strip().upper().startswith("Y")
    return confirm

guard = Guard(tier2={
    cat: make_confirmer(cat, gemma) for cat in (
        Category.HATE, Category.UNSAFE_ADVICE, Category.SELF_HARM,
        Category.SEXUAL, Category.VIOLENCE, Category.ILLEGAL, Category.TOXICITY,
    )
})
```

비용: certain 히트(secret/pii/명시적 위험)는 모델을 부르지 않으므로, 모델 호출은 *애매한
콘텐츠 히트가 난 응답*과 *그 카테고리 미탐 응답*에만 발생한다. 식약처처럼 이미 LLM 이 서빙
중인 환경에선 한계비용이 작다.

검증: 동작은 `tests/test_tier2_escalation.py`. 결정론 floor 무회귀는 전체 스위트로 보장.
