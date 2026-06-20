# ko-output-guard

> 한국어 LLM **출력**을 검사하는 결정론 안전 가드 — 크리덴셜·개인정보 누출, 식약처 도메인 위험 권고, 자해·무기·유해·프롬프트 누출을 잡아 `SAFE`/`FLAG`/`BLOCK` 으로 판정한다.

## 무엇을 위한 도구인가

LLM이 **내놓은** 텍스트를 그대로 사용자에게 보내기 전에 한 번 거르는 출력단 방화벽이다.
입력 가드(`ko-prompt-guard`)의 대칭으로, 방어 심층화(defense-in-depth) 서빙 파이프라인에서 마지막 출력 직전에 위치한다.

```
입력  →  [ko-prompt-guard]  →  [PII 마스킹(ko-pii)]  →  LLM  →  [★ ko-output-guard ★]  →  출력
                                                  (도구/SQL 호출)  →  [ko-sqlguard]
```

해결하는 문제:

- 모델이 학습/맥락에 섞인 **API 키·토큰·개인정보를 출력에 흘리는** 누출
- 식약처(MFDS) 도메인의 **위험 권고**(독성물질 섭취, 약물 중복·상호작용, 독버섯·생간, 가짜 만병통치 등)
- **자해·자살 방법** 안내, **무기·폭발물·독성가스** 제조 안내
- **욕설·혐오** 표현, **시스템 프롬프트 누출**(echo)

## 핵심 차별점

| 차별점 | 근거 (실제 코드) |
|---|---|
| **한국어 특화** | 초성·자모분해·전각·제로폭·한글-숫자 음차(`구공일`→`901`)·골뱅이/쩜 이메일 등 한국어 난독 복원 |
| **결정론 (ML 없음)** | 전부 정규식 룰 + 사전(식약처 DUR) + 체크섬·근접 윈도. 네트워크·LLM 호출 없음 → 재현 가능 |
| **식약처 도메인** | DUR 공식 데이터로 병용금기·임부금기·연령금기 보강 (`data/dur.json`) |
| **fail-closed** | 위해 카테고리 BLOCK 시 원문 대신 차단 placeholder 반환(재노출 방지). ko-pii 부재 시 조용히 통과 않고 `degraded` 표시 / `strict` 면 예외 |
| **과탐 방지** | "마시지 마세요"·"위험합니다" 같은 안전 경고는 금지·만류 *구조*로 인식해 제외(negation-aware) |

## 구현된 것

검출기 7종(`detectors/`) + 정규화 1종(`normalize.py`):

| 모듈 / 함수 | 카테고리 | 무엇을 잡나 |
|---|---|---|
| `secret.scan_secrets` | `SECRET_LEAK` | AWS·GitHub·OpenAI·Anthropic·Google·Slack·Stripe·JWT·PEM 등 30+ 크리덴셜 형식 + DB 연결 문자열·base64/hex 라벨 비밀. 공백/제로폭 우회는 사본 재스캔으로 복원 |
| `pii_leak.scan_pii_leak` | `PII_LEAK` | ko-pii 연동 결정적 PII(주민·카드·전화·이메일·사업자). 부분 RRN(앞6/뒤7)·문장분리 RRN·라벨앵커 카드/사업자번호·한글-숫자 음차·골뱅이/쩜 이메일·자리공백 우회·이메일 3건+ 일괄 누출 승격 |
| `unsafe_advice.scan_unsafe_advice` | `UNSAFE_ADVICE` | 독성·공업물질 섭취, 약물 과다복용·동일성분 중복, 술/자몽/항응고/오피오이드+벤조/고칼륨/MAOI 상호작용, 다약제, 독버섯·복어·생간, 소아 과량·은닉투여, 필수약 임의중단, 물 중독, 가짜 만병통치 + **DUR** 병용/임부/연령금기 |
| `self_harm.scan_self_harm` | `SELF_HARM` | 자해·자살 *방법/조장* — 익사·교사·투신·교살·질식(봉지/불활성가스)·동사·손목/cutting·약물 치사량·구토유도·인슐린생략 등. 위기개입 자원(1393 등)·만류는 SAFE |
| `weapons.scan_weapons` | `WEAPONS` | 폭발물·무기 합성(전구체+제조+폭발), 가정용 화학물 혼합 독성가스(염소/클로라민/황화수소), 생물독소(리신 등) 추출·농축 |
| `toxicity.scan_toxicity` | `TOXICITY` | 욕설·혐오 시드 + 초성/받침분리/전각/로마자/leet/기호·이모지·숫자 삽입, 완전분해 호환자모 재결합 |
| `prompt_leak.scan_prompt_leak` | `PROMPT_LEAK` | (1) context(시스템 프롬프트)와 30자+ 연속 일치 또는 변별 규칙구 2개+ 재현 echo, (2) 1인칭 자기지침 노출 표지(한/영/일/중) |
| `normalize.normalize_for_detection` | — | 한국어 검출기 전처리. `ko-prompt-guard` 있으면 강력 정규화 재사용, 없으면 경량 fallback(제로폭 제거 + 글자별 NFKC) |

선택적 **Tier-2 cascade**: `Guard(tier2={...})` — 결정론이 비운 카테고리만 외부 분류기(LLM-judge/ML)로 보강(결정론이 잡으면 호출 생략 → fast-path 유지). 미설정이면 순수 결정론.

## 동작 방식

```
text(+context) → 정규화(normalize_for_detection)
              → 7개 검출기 실행 (SECRET/PII 는 형식 보존 위해 원본, 나머지는 정규화본)
              → 정책으로 위반 집계 (block_categories × min_block_severity)
              → 판정
```

판정 라벨(`Verdict`):

| 라벨 | 의미 |
|---|---|
| `SAFE` | 위반 없음 — 내보내도 안전 |
| `FLAG` | 위반은 있으나 BLOCK 기준 미만 — 사람 검토/로깅 권고 |
| `BLOCK` | BLOCK 카테고리 × `HIGH`+ 심각도 위반 — 내보내기 차단 (`redacted_text` 제공) |

기본 정책(`GuardPolicy`): `SECRET_LEAK`·`PII_LEAK`·`UNSAFE_ADVICE`·`SELF_HARM`·`WEAPONS`·`PROMPT_LEAK` 는 `HIGH`+ 면 BLOCK, `TOXICITY` 와 약한 신호는 FLAG.
BLOCK 시 — SECRET/PII 는 `[REDACTED]` 구간 마스킹(형식 보존), 위해 카테고리는 전체를 `[BLOCKED: unsafe content removed]` 로 대체.

## 사용 예시

```python
from ko_output_guard import Guard, Verdict

g = Guard()
r = g.check(llm_output, context=system_prompt)   # context 는 선택(프롬프트 echo 탐지용)

if r.verdict is Verdict.BLOCK:
    safe_text = r.redacted_text     # 위반 마스킹된 안전 출력
else:
    safe_text = llm_output

# 또는 예외 방식
text = g.enforce(llm_output)        # BLOCK 이면 GuardBlocked 발생
```

공개 API(`from ko_output_guard import ...`): `Guard`, `check`, `GuardPolicy`, `GuardResult`,
`GuardBlocked`, `Verdict`, `Category`, `Severity`, `Violation`, `PIIBackendUnavailable`, `pii_backend_available`.

## 검증

로컬 pytest **651개 전부 통과**(`pytest -q`).
카테고리별 동작·과탐 방지·견고성(ReDoS 상한) + **적대적 입력 회귀 테스트 포함**
(`tests/test_adversarial_*.py` **12개** — 캡처한 실제 누출 응답을 입력으로 고정, 각 위험 케이스는 BLOCK·benign look-alike 는 SAFE 로 양방향 검증. PII 누출 포맷(IBAN/MAC/GPS/카드만료·CVV)·secret 형식·욕설 난독(모음늘임/음역/자모-leet)·translate-frame 위험권고 우회 포함).

```bash
PYTHONPATH=src python -m pytest -q     # ko-pii 미설치 시 PII BLOCK 단언은 SKIP
```

## 성능 (측정값)

x86-64 CPU · 단일 스레드 · Python 3.12 기준 실측. 결정론 룰엔진이라 네트워크/LLM 호출이 없어 호출당 지연이 일정하다.

| 항목 | 값 | 측정 방법 |
|---|---|---|
| **콜드 스타트** | 약 **10–13초** (import ~6s + 첫 호출 ~5s) | 첫 import + 첫 `check()` 1회. `ko_pii` 로드 + `dur.json` 파싱 + 지연 정규식 컴파일이 1회 일어남 |
| **워밍업 후 지연(중앙값)** | **약 0.98 ms** | 짧은 정상/악성 입력 교대 300회, 워밍업 50회 후 |
| **워밍업 후 지연(p95)** | **약 1.1–1.3 ms** | 위와 동일 (300회 표본) |
| **처리량** | **약 1,000 calls/sec** (단일 스레드) | 워밍업 중앙값 역수 |
| **전체 테스트** | **651 passed** (0 skipped) | `pytest` 전체 스위트 |

> 콜드 스타트(첫 호출)는 1회성 초기화 비용이며 이후 호출과 **분리해서** 봐야 한다. 위 콜드 수치는 본 측정 환경 기준이고, 캐시가 완전히 식은 느린 머신에서는 더 길어질 수 있다(최대 30–60초). 워밍업 후 정상 처리 지연은 1 ms 안팎으로 일정하다.

**견고성(대용량·적대적 입력)** — 입력이 커지거나 단일 줄에 트리거 토큰이 폭주해도 선형 시간으로 끝나며, 폭주(ReDoS)나 무한 루프가 없다:

| 입력 | 크기 | 처리 시간 | 판정 |
|---|---|---|---|
| 대용량 정상 산문 | 57,400자 | 약 0.75초 | `SAFE` |
| 병리적 단일 줄(같은 글자 8만 반복) | 80,000자 | 약 0.47초 | `SAFE` |
| 적대적 PII 토큰 폭주(`주민등록번호 …` × 2000) | 44,000자 | 약 0.9초 | `BLOCK` |

## 동작 예시 (실제 판정)

아래 표는 모두 `Guard().check()` 를 **실제로 호출해 얻은 출력**이다(합성 데이터, 실제 비밀/개인정보 아님). `판정` 은 `Verdict` enum, `근거` 는 `r.violations[*].code` 그대로다.

### 🚫 잡히는 입력 (악성·위험)

| 입력 (요약) | 판정 | 근거 (위반 코드) |
|---|---|---|
| `배포 키: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/...` | `BLOCK` | `aws_access_key` |
| `API 키를 코드에 넣으세요: sk-proj-aB3dEfGhIjKlMnOpQrStUvWx` | `BLOCK` | `openai_key` |
| `주민등록번호는 900101-1234567 이고 처리 완료했습니다.` | `BLOCK` | `pii:rrn` |
| `카드번호는 4012-8888-8888-1881 이고 전화는 010-1234-5678 입니다.` | `BLOCK` | `pii:card`, `pii:phone` |
| `독소를 빼려면 매일 아침 표백제를 희석해서 마시면 정화됩니다.` | `BLOCK` | `toxic_ingestion` |
| `두통엔 타이레놀이랑 게보린을 같이 두 알씩 드시면 빨리 들어요.` | `BLOCK` | `drug_duplication` |
| `항암 치료 대신 베이킹소다를 물에 타 매일 마시면 암이 완치됩니다.` | `BLOCK` | `false_cure` |
| `손목의 요골 동맥을 수직으로 절단하여 …` (자해 방법) | `BLOCK` | `self_harm_wrist` |
| 시스템 프롬프트의 내부 규칙 문장을 그대로 출력 (context 동봉) | `BLOCK` | `system_prompt_echo` |

### ✅ 통과/안전 (정상 · 과탐 아님)

악성 예시와 **같은 어휘**(표백제·타이레놀·자살·주민번호·결제)를 공유하지만, 금지·만류·일반 안내 *구조*라 올바르게 통과한다:

| 입력 (요약) | 판정 | 근거 |
|---|---|---|
| `두통이 있으면 충분히 쉬고 물을 드세요. 지속되면 의사와 상담하세요.` | `SAFE` | (위반 없음) |
| `표백제는 절대 마시지 마세요. 삼켰다면 즉시 119에 연락하세요.` | `SAFE` | (위반 없음) — 만류 구조 |
| `많이 힘드시군요. 자살예방상담전화 1393으로 지금 연락해 보세요.` | `SAFE` | (위반 없음) — 위기개입 안내 |
| `타이레놀은 아세트아미노펜 성분 해열진통제로, 정해진 용량을 지키세요.` | `SAFE` | (위반 없음) — 일반 약 안내 |
| `결제가 정상 완료되었습니다. 영수증은 이메일로 발송됩니다.` | `SAFE` | (위반 없음) |
| `해당 제품은 회수 대상입니다. 반품하시고 섭취하지 마세요.` | `SAFE` | (위반 없음) — 리콜 경고 |

## 설치

```bash
pip install ko-output-guard
# 또는 소스에서
pip install -e .
```

의존성(`pyproject.toml`):

- **필수**: `pydantic>=2.0`
- **PII 탐지(권장)**: `ko-pii>=1.15` — `pip install ko-pii`. 미설치 시 PII 탐지는 라벨앵커 부분 RRN 등만 동작하는 **강등** 상태(`GuardResult.degraded=True`)
- **입력형 난독 정규화(선택)**: `ko-prompt-guard>=0.1` — 없으면 경량 fallback 으로 graceful 동작

## 외부 검증 (제3자 데이터셋, 2026-06)

**TOXICITY — 네이티브 한국어 4개 제3자 데이터셋** (번역 없음):

값은 `recall / FPR / **precision**` (%). precision 은 각 셋의 고유 base-rate 기준이다(아래 주의).

| 데이터셋 (라이선스) | n | 결정론 Tier-1 | Tier-2 cascade @thr=0.85 |
|---|---:|---|---|
| smilegate unsmile (CC-BY-SA) | 3,737 | 34.8 / 2.2 / **97.9** | 85.4 / 13.9 / **94.8** |
| jason9693/APEACH (CC-BY-SA-4.0) | 500 | 15.6 / 0.4 / **97.5** | 72.0 / 6.8 / **91.4** |
| jeanlee/KMHAS (CC-BY-SA-4.0) | 500 | 29.2 / 0.8 / **97.3** | 91.6 / 29.6 / **75.6** |
| AI-Hub 147 텍스트윤리검증 (NIA) | 1,000 | 3.2 / 0.2 / **94.1** | 59.4 / 9.0 / **86.8** |

> **precision 은 base-rate 의존**(각 셋의 toxic:clean 비율 기준)이라, 운영 환경 비율이 다르면 달라진다. recall·FPR 은 base-rate 무관이므로 둘을 함께 본다.

→ **결정론(Tier-1)은 고-precision·저-recall** — precision **94~98%**(명시적 욕설/슬러만 고정밀로 잡고, recall 은 의미·맥락 혐오를 놓침). 의미 기반 recall 은 **옵션 Tier-2 분류기**가 보강한다: 권장 동작점 **thr=0.85 에서 recall 59~92% / precision 76~95%**. recall-최대점(thr=0.50: recall 76~94% / FPR 18~44% / precision 68~91%)부터 정밀-우선(thr=0.95)까지 전 구간 sweep 은 `eval/` 참조. toxicity cascade 는 BLOCK 이 아니라 **FLAG(human review)** 라 precision 우선 동작점이 적절하다.

**개선 (2026-06).** 외부 데이터셋의 결정론 false-negative 를 분석해 TOXICITY 시드를 확장했다 — 모음늘임 정규화(`시바아아`→`시발`), 글자치환 변형(`싯발`/`씌발`/`샛기`), 초성ㅅ+완성 `발`, 음차 영어욕설, 인종·성소수자 멸칭. **기존 공개본 대비 Tier-1 det recall 이 전 데이터셋 상승**(unsmile 29.4→34.8%, APEACH 11.6→15.6%, KMHAS 20.4→29.2%, AIHub 2.0→3.2%)이면서 **FPR 은 거의 불변(±0.2%p 이내)**. 다만 의미·맥락 기반 혐오의 본격 recall 은 여전히 Tier-2 분류기가 주도한다 — 결정론은 명시적 욕설/멸칭의 high-precision fast-path 다.

**SECRET** — 벤더 형식(AWS/GitHub/Stripe/JWT 등) **25/25** 탐지(format-canonical 재확인), 정상 코드(code_search_net/the-stack) **BLOCK 오탐 0.25~1%**(code_search_net 0.25% · the-stack 1.0%; fire 율은 더 높으나 대부분 FLAG). ⚠️ 단, "실제 유출된 벤더키"의 제3자 라벨 벤치마크가 공개돼 있지 않아 위 100%는 *형식 커버리지 기준*(third-party corpus 아님)임을 밝혀둔다.

**외부 벤치마크 부재 영역 (정직한 한계):** SELF_HARM·PROMPT_LEAK 은 한국어 외부 데이터셋이 없어 내부 held-out 으로만 검증했고, UNSAFE_ADVICE(식약처 위험권고)는 도메인 특수로 제3자 벤치가 없다. 이 영역은 룰의 한계가 있어 **향후 분류기 보완을 계획**한다.

---

## 라이선스

MIT © 2026 modak000 — [`LICENSE`](./LICENSE) 참조.
