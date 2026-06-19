"""위험 권고 탐지 — 식약처(MFDS) 도메인 차별점.

발표자료의 실제 사고 사례를 막는다: 독성/공업 물질 섭취 권장, 약물 과다복용,
동일성분 중복 복용. 결정론 룰의 한계상 *명백한 권장*만 잡고(의미적 위험은 Tier-2),
안전 경고('마시지 마세요'/'위험합니다')는 negation 맥락으로 제외해 과탐을 막는다.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..result import Category, Severity, Violation

# 식약처 DUR(의약품안전사용서비스) 공식 데이터 — 상호작용/금기를 추측이 아니라 공식
# 병용금기/임부금기/연령금기로 보강. data/dur.json 은 crawl DUR 성분정보에서 생성.
# 파일 누락/손상으로 import 자체가 깨지면 가드 전체가 죽으므로(OG-9) 빈 DUR 로 graceful
# 강등한다 — 나머지 패턴 룰은 정상 작동, DUR 보강만 비활성된다.
try:
    _DUR = json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "dur.json").read_text("utf-8"))
except (OSError, ValueError):
    _DUR = {"pairs": [], "preg": [], "age": [], "ingredients": []}
_DUR_PAIRS = frozenset(frozenset(p) for p in _DUR["pairs"])   # 병용금기 성분쌍
_DUR_PREG = frozenset(_DUR["preg"])                            # 임부금기 성분
_DUR_AGE = frozenset(_DUR["age"])                             # 연령금기 성분
# 성분 목록이 비면 매칭 불가능한 패턴(빈 alternation 은 모든 위치 매칭)이 되므로 가드.
_DUR_INGR_RE = re.compile("|".join(
    re.escape(i) for i in sorted(_DUR["ingredients"], key=len, reverse=True))
    or r"(?!x)x")  # 빈 목록이면 절대 매칭 안 되는 패턴
_DUR_REC = re.compile(r"같이|함께|병용|동시|섞어|타서|드세요|드시|복용|곁들")

# 섭취하면 위험한 독성/공업 물질
_TOXIC = (
    r"표백제|락스|메탄올|공업용\s*(?:알코올|알콜)|부동액|살충제|농약|청산가리|아세톤|"
    r"신나|본드|가성소다|양잿물|일산화탄소|포름알데히드|에틸렌\s*글리콜|제초제|쥐약|"
    r"세제|구연산\s*나트륨\s*과다|표백\s*성분|"
    # 식약처 사고 사례 보강: 담배·니코틴, 브로민(염소 제거 식단), 공업·독성 물질
    r"담배\s*(?:진액|농축액)|니코틴\s*(?:원액|농축)?|브로민|브롬화\s*나트륨|소독용\s*에탄올|"
    r"공업용\s*글리세린|메틸알코올|왁스|등유|휘발유|시너|라이터\s*기름|방충제|"
    # 흔한 우회 별칭(가습기 살균제·전자담배 액상 등 실제 사고 물질)
    r"전자담배\s*(?:액상|리필액?|원액)|가습기\s*살균제|냉각수|살균\s*농축액|"
    # MMS/이산화염소 미신, 수은, 변기·청소용 락스 별칭
    r"차아염소산\s*나트륨|이산화염소|MMS|수은|변기\s*청소(?:용|제)|청소용\s*락스|"
    # MMS 별칭 보강: 소듐 클로라이트/아염소산 나트륨(이산화염소 발생제) — '식품 등급'
    # 수식으로 안전한 척 위장하는 실제 사례. 영문 표기도 함께.
    r"소듐\s*클로라이트|아염소산\s*나트륨|sodium\s*chlorite|"
    # 가짜 만병통치(false-cure)로 섭취 권장되는 공업·세정 물질: 붕사(borax),
    # 과산화수소, 베이킹소다(중조) 다량 섭취. 식용 소량 베이킹소다와 혼동 없도록
    # _INGEST 동사 게이팅에 의존(아래 toxic_ingestion 룰). 영문 표기 병기.
    r"붕사|borax|과산화수소|hydrogen\s*peroxide"
)
# 약물 상호작용 룰용 어휘 — 술/약물군.
_ALCOHOL = r"술|소주|맥주|와인|막걸리|위스키|음주|반주|한\s*잔"
_RX = r"약|수면제|진정제|항생제|진통제|혈압약|당뇨약|항우울제|신경안정제|감기약"
# 동일/동계열 중복 복용 위험 약물(NSAID·해열진통 계열 확장).
_DUP_DRUGS = (r"타이레놀|게보린|펜잘|사리돈|아세트아미노펜|이부프로펜|나프록센|아스피린|"
              r"낙센|부루펜|덱시부프로펜|아세클로페낙|세토펜|타세놀|탁센")
# MAOI(모노아민 산화효소 억제제) 실제 성분 로스터 — 클래스명만으로는 마케팅 카피를
# 못 잡으므로 KO+EN 성분명으로 트리거. 숙성 치즈/와인(티라민)과 병용 시 고혈압 위기.
_MAOI = (r"페넬진|트라닐시프로민|이소카르복사지드|셀레길린|selegiline|phenelzine|"
         r"isocarboxazid|tranylcypromine|모클로베미드|moclobemide|"
         r"MAO\s*억제제|마오\s*억제제|MAOI")
# 오피오이드(마약성 진통제) + 벤조디아제핀/Z-drug 병용 — 둘 다 중추신경 억제제라
# 호흡억제·사망 위험(블랙박스 경고). DUR 쌍에 없어 전용 룰로 잡는다. 성분/상품명 KO 병기.
_OPIOID = (r"옥시코돈|옥시콘틴|펜타닐|트라마돌|코데인|모르핀|하이드로코돈|하이드로모르폰|"
           r"oxycodone|fentanyl|tramadol|codeine|morphine")
_BENZO = (r"디아제팜|알프라졸람|로라제팜|클로나제팜|자낙스|벤조(?:디아제핀)?|졸피뎀|"
          r"트리아졸람|미다졸람|diazepam|alprazolam|lorazepam|clonazepam|zolpidem|xanax")
# 고칼륨혈증 위험쌍 — 칼륨 보충제 + ACE/ARB 또는 칼륨보존 이뇨제. DUR 밖이나 위험.
_POTASSIUM = r"염화칼륨|칼륨\s*보충(?:제)?|포타슘|potassium"
_K_RAISING_RX = (r"에날라프릴|리시노프릴|라미프릴|페린도프릴|캡토프릴|로사르탄|발사르탄|"
                 r"칸데사르탄|텔미사르탄|ACE\s*억제(?:제)?|ARB|스피로놀락톤|에플레레논|"
                 r"아밀로라이드|트리암테렌|enalapril|lisinopril|ramipril|losartan|spironolactone")
# HMG-CoA 환원효소 억제제(스타틴) 성분 로스터 — 자몽과 병용 시 횡문근융해. 클래스명
# '콜레스테롤약'만으로는 성분명 카피('심바스타틴+자몽')를 놓치므로 KO+EN 성분명으로 보강.
_STATIN = (r"심바스타틴|아토르바스타틴|로수바스타틴|프라바스타틴|플루바스타틴|피타바스타틴|"
           r"로바스타틴|simvastatin|atorvastatin|rosuvastatin|pravastatin|fluvastatin|"
           r"pitavastatin|lovastatin")
# 가짜 만병통치(false-cure) 명명 엔티티 — 암 완치/항암 대안을 표방하는 비과학 요법.
# R4 보강: 콜로이드 은(띄어쓰기·'달' 없는 변형)과 이버멕틴/이베르멕틴(말 구충제) 추가.
# 기존 별칭은 보존하고 alternation 만 더한다(recall-safe).
_FALSE_CURE = (r"차가버섯|살구씨|아미그달린|비타민\s*B17|B17|레이어트릴|laetrile|amygdalin|"
               r"베이킹\s*소다|중탄산\s*나트륨|중조|콜로이달\s*실버|은\s*콜로이드|colloidal\s*silver|"
               r"콜로이드\s*은|이버멕틴|이베르멕틴|ivermectin|말\s*페이스트|말\s*구충제|"
               r"게르손|커피\s*관장|붕사|borax|과산화수소|hydrogen\s*peroxide|MMS|이산화염소")
# 완치·항암대안 주장 앵커 — 가짜 치료 카피의 핵심 시그널.
# R4 보강: 코로나/바이러스 완치·박멸 주장도 받는다('코로나를 치료/바이러스를 죽') —
# 기존 암·만병통치 앵커는 그대로 두고 alternation 추가(recall-safe).
_CURE_CLAIM = (r"암\s*(?:완치|치료|낫|박멸|소멸)|항암(?:\s*치료)?\s*(?:대안|대신)|"
               r"코로나(?:바이러스)?\s*(?:를|가|에)?\s*(?:치료|완치|낫|박멸|죽|회복)|"
               r"바이러스\s*(?:를|가)?\s*(?:죽|박멸|치료|없애)|covid|코로나\s*치료|"
               r"기적|완치|만병통치|병이?\s*낫|치료법|효능")
# 디곡신(강심배당체) 상호작용 로스터 — DUR 쌍에 없는(루프/티아지드 이뇨제, 일부 CCB)
# 위험 병용을 전용 룰로 잡는다. 단일 약 언급은 페어 게이팅으로 미발화(recall-safe).
_DIGOXIN = r"디곡신|digoxin"
# 디곡신과 함께 저칼륨/농도상승 위험을 키우는 약물군: 루프·티아지드 이뇨제 + 일부 CCB.
_DIGOXIN_PARTNER = (r"푸로세미드|푸로세마이드|furosemide|토르세미드|부메타니드|"
                    r"히드로클로로티아지드|하이드로클로로티아지드|티아지드|"
                    r"베라파밀|verapamil|딜티아젬|diltiazem|이뇨제")
# 세로토닌 증후군 위험 — 트립탄(편두통) + SSRI/SNRI 또는 MAOI 병용. 둘 다 세로토닌
# 작용을 키워 고열·경련·사망 위험. 성분 KO+EN 로스터(클래스명 우회 차단), 페어 게이팅.
_TRIPTAN = (r"수마트립탄|졸미트립탄|나라트립탄|리자트립탄|일레트립탄|알모트립탄|"
            r"sumatriptan|zolmitriptan|naratriptan|rizatriptan|트립탄")
_SEROTONERGIC = (r"서트랄린|세르트랄린|sertraline|플루옥세틴|fluoxetine|파록세틴|paroxetine|"
                 r"에스시탈로프람|escitalopram|시탈로프람|citalopram|벤라팍신|venlafaxine|"
                 r"둘록세틴|duloxetine|렉사프로|졸로프트|프로작|SSRI|SNRI|항우울제")
# 시메티딘(CYP 억제) + 와파린/항응고 — 출혈 위험. 시메티딘은 DUR ingredient 가 아니라 전용.
_CIMETIDINE = r"시메티딘|cimetidine"
# 긍정-추천 앵커 — 마케팅 카피는 명령형 동사 대신 추천 명사로 권장을 표현한다
# ('완벽한 시너지', '마음껏', '즐기세요'). 위험 엔티티 페어로 게이팅돼 단독 등장 FP 없음.
_ENDORSE = (r"시너지|조합|완벽|마음껏|두\s*배|더\s*효과|즐기|추천|곁들|함께|같이|"
            r"드세요|드시|복용|괜찮")
# 아동 대상 위해 약물 — 진정·향정·수면 계열(분유·해열 시럽 같은 정상 투약과 구분).
_CHILD_HARM_DRUG = (r"수면제|수면\s*유도제|진정제|신경안정제|항우울제|향정신|졸피뎀|벤조|"
                    r"멜라토닌|디펜히드라민|항히스타민|아편|모르핀|마취제|안정제|"
                    r"성인용\s*약|어른\s*약|어른\s*용량|성인\s*용량")
# 은닉·진정 목적 단서 — 정상 소아 투약과 결정적으로 구분되는 신호.
_COVERT = (r"갈아|몰래|모르게|타서|타\s*먹|섞어|숨겨|숨기|섞어\s*먹이|"
           r"재우려|재우기\s*위|잠재우|잠\s*재우|얌전(?:히)?\s*(?:시키|만들)|조용히\s*시키")
# 투여 동사(아동 대상).
_ADMIN = r"먹이|먹여|드세요|줘|주세요|투여|복용|먹게|마시게|삼키게"
# 섭취/체내 투입 동사 — 가글·머금·모금 등 우회 표현 포함.
_INGEST = (
    r"(?:드세요|드시(?:면|고|길|는)|마시(?:세요|면|고|는|라|어)|마셔|섭취|복용|먹(?:어|으면|도|는|자|이|였)|"
    r"들이키|삼키|가글|머금|입에\s*넣|한?\s*모금|들이부|원\s*샷|복용량|"
    # 사동(먹이-)·비경구 경로(흡입/주사/주입/도포 흡수)도 위험 투여로 본다.
    r"흡입|들이마시|관장|핥|주사|주입|발라\s*흡수|피부에\s*발라|"
    # 격식·평서형 종결('…마십니다/마신다/마시기/드십니다/섭취합니다/복용합니다')도 투여로
    # 본다 — recipe 말미가 명령형이 아니라 평서·격식체로 끝나는 모델 출력 우회를 막는다.
    # _TOXIC 엔티티 동시 등장으로 게이팅돼 '물을 자주 마십니다' 같은 benign 은 발화 안 됨.
    r"마십니다|마신다|마시기|마셨|드십니다|섭취(?:합니다|한다|하기|했)|복용(?:합니다|한다|하기|했)|"
    r"drink|swallow|ingest|gargle|consume|inhale|inject)"
)
# 자연 독소 식품/약초 — 가정 조리·섭취 권장 시 위험. 복어(테트로도톡신, 가열해도 잔존),
# 컴프리(피롤리지딘 알칼로이드 간독성). 조리/섭취 동사로 게이팅해 단순 언급
# ('복어는 독이 있습니다', '컴프리 식별법')은 발화하지 않게 한다(recall-safe, _INGEST 미러).
_TOXIC_FOOD = (r"복어\s*(?:내장|알|간|껍질|손질)|컴프리|피롤리지딘")
_TOXIC_FOOD_VERB = (r"손질|끓|조리|우려|차로|차\s*마|드세요|드시|먹|마시|섭취|"
                    r"넣고|고아|달여|달이")
# 생간·생고기 회 — 기생충/E형 간염. 가열하면 안전해지므로(복어와 달리) '익혀/가열/끓여'가
# 동사 직전에 오면 안전한 조리 권고('익혀 드세요')이니 제외한다. 명령형 raw-섭취 동사만 잡는다.
_RAW_MEAT = (r"돼지\s*생간|멧돼지\s*생고기|생고기\s*회|소\s*생간|생간\s*회")
# 영문 위험 권고 — 한글과 어순이 반대(동사 먼저)라 양방향으로 본다. 영문 전용이라 한글 FP 없음.
_TOXIC_EN = r"bleach|methanol|antifreeze|nicotine|kerosene|gasoline|lye|ethylene\s*glycol|rat\s*poison"
_INGEST_EN = r"drink|swallow|ingest|gargle|consume|sip|chug"

# OG-1 fix — bare 안전 토큰(주의/위험/병원) 한 단어가 문장 어디든 있다고 위험 권고를
# 무력화하면 공격자가 끝에 '주의'만 붙여 우회한다('표백제를 드세요 주의'). 그래서 단순
# 키워드 존재가 아니라 *금지/만류 구조*(위험 동작 동사에 인접한 부정·금지·결과경고)일
# 때만 경고로 인정한다. 진짜 경고는 ① 금지('마시지 마세요/먹으면 안 됩니다'), ② 만류
# ('권하지 않습니다'), ③ 안내-회피('약사와 상의/병원에 가세요/피하세요'), ④ 조건-결과
# ('드시면 위험/출혈/손상')처럼 동작에 결합된 구조를 갖는다. bare 'imperative + 주의'는 X.
_WARNING_STRUCTURE = re.compile(
    # ① 금지: 동작/동사 + (지/면/…) + 마세요/안 되/금지/삼가/자제
    r"(?:마시|먹|드시|드세|섭취|복용|들이|삼키|핥|흡입|주사|주입|발라|피우|매|하)\s*"
    r"(?:지|으면|면|어도|셔도|는\s*것은?)?\s*"
    r"(?:마세요|마십|말[고라]|안\s*[되돼됩된]|금지|삼가|자제)"
    r"|피하세요|피하십|피하시"
    # ② 만류: 권하지 않 / 권장하지 않 / 권유하지 않
    r"|권(?:하|장|유)지?\s*않"
    # ③ 안내-회피: …약사/의사/전문가/병원/응급 + 상담/상의/확인/가세요/방문
    r"|(?:약사|의사|전문가|병원|응급)\s*(?:와|에|을|를)?\s*(?:상담|상의|확인|가세요|방문)"
    # ④ 조건-결과: (동작/중단)면/시면/으면/하면 … (해악어). 섭취뿐 아니라 중단('끊으면
    # 위험')도 — 조건절+해악 결합이라 bare 키워드 우회와 구조적으로 다르다.
    # \w* 무한 반복은 '끊끊끊…' 같은 반복 입력에서 백트래킹 ReDoS 를 부른다 — 한국어
    # 어간+어미는 짧으므로 \w{0,12} 로 캡한다(실제 매칭 보존, 의미 동일, 백트래킹 제거).
    r"|(?:마시|먹|드시|복용|섭취|끊|중단|그만|놓치|빼먹)\w{0,12}\s*(?:면|시면|으면|하면)"
    r"[^.\n]{0,16}?"
    r"(?:위험|독성|중독|사망|손상|출혈|멍|부작용|사고|쇼크|마비|발작|해롭|악화|중복)"
)
# 경고어 직후에 부정(않/없/아니)이 오면 '위험하지 않다'식 안심 권고이므로 경고로 치지 않는다.
_NEG_AFTER = re.compile(r"하지\s*않|지\s*않|없|아니")

# 영문 경고/만류 구조 — 한글 룰과 대칭. 'do not drink bleach, it is dangerous'(안전 안내)는
# SAFE, 'you should drink bleach'(권장)는 BLOCK 으로 구분(OG-9). bare 'dangerous'가 아니라
# 금지(do not/never/avoid)나 명시 경고(is dangerous/toxic/poisonous/harmful) 구조여야 한다.
_WARNING_STRUCTURE_EN = re.compile(
    r"(?i)\b(?:do\s*not|don't|never|avoid|must\s*not|should\s*not|shouldn't|"
    r"cannot|can't|refrain\s*from|is\s*(?:very\s*)?dangerous|are\s*dangerous|"
    r"is\s*toxic|is\s*poisonous|harmful|do\s*not\s*ingest)\b"
)


def _sentence_bounds(text: str, s: int, e: int) -> tuple[int, int]:
    """매칭이 속한 문장(. ! ? 줄바꿈 경계)의 (left, right) 오프셋. 경계 탐색은
    bounded rfind/find 라 선형 — 큰 텍스트에서도 매칭당 O(1)~O(경계간격)이다."""
    bounds = [text.rfind(c, 0, s) for c in (".", "!", "?", "\n")]
    left = max(bounds) + 1 if max(bounds) >= 0 else 0
    ends = [x for x in (text.find(c, e) for c in (".", "!", "?", "\n")) if x != -1]
    right = min(ends) if ends else len(text)
    return left, right


def _sentence_span(text: str, s: int, e: int) -> str:
    """매칭이 속한 문장 전체 문자열 — 좁은 윈도로는 문장 끝 경고('…위험이 있으니 주의')를
    놓쳐 정상 경고가 과탐되므로 문장 단위로 본다."""
    left, right = _sentence_bounds(text, s, e)
    return text[left:right]


def _has_genuine_warning(sentence: str) -> bool:
    """문장에 진짜 안전경고 *구조*가 있는지. bare 키워드(주의/위험) 존재만으로는 안 되고
    금지·만류·안내회피·조건결과 구조여야 한다(OG-1). '위험하지 않다'식 부정 안심은
    경고가 아니라 오히려 위험 권고를 강화하므로 그런 매칭은 무시한다(negation-aware)."""
    for m in _WARNING_STRUCTURE.finditer(sentence):
        if not _NEG_AFTER.search(sentence[m.end():m.end() + 8]):
            return True
    return bool(_WARNING_STRUCTURE_EN.search(sentence))

_PATTERNS: list[tuple[re.Pattern[str], Severity, str]] = [
    # 독성/공업 물질 + 섭취 권장. filler 윈도를 {0,40}으로 넓혀(OG-9) 물질↔동사 사이에
    # 수식어를 끼워 우회('표백제를 컵에 잘 희석한 다음 천천히 드세요')하는 걸 막는다.
    # 경고 문장은 _has_genuine_warning 으로 별도 억제되므로 FP 위험 없음.
    (re.compile(rf"(?:{_TOXIC})[^.\n]{{0,40}}?{_INGEST}"), Severity.CRITICAL, "toxic_ingestion"),
    # 영문 위험 권고(동사↔물질 양방향)
    (re.compile(rf"(?:{_INGEST_EN})[^.\n]{{0,20}}?(?:{_TOXIC_EN})|"
                rf"(?:{_TOXIC_EN})[^.\n]{{0,20}}?(?:{_INGEST_EN})", re.IGNORECASE),
     Severity.CRITICAL, "toxic_ingestion"),
    # 약물 과다복용 권장 — 배수·다량·여러 + 수치('N정/N알'), 비수치 과량어(한 움큼/한 통)
    (re.compile(
        r"(?:권장량[^.\n]{0,6}?(?:초과|넘게|이상|보다\s*많)|두\s*배|세\s*배|[2-9]\s*배|\d{2,}\s*배|"
        r"배로\s*늘|한꺼번에|여러\s*(?:알|정|개|봉)|한\s*번에\s*[3-9]\s*(?:정|알|개|캡슐|봉)|"
        r"[5-9]\s*(?:정|알|캡슐|개)\s*(?:씩|을|이상|더)?|\d{2,}\s*(?:정|알|개|봉|캡슐|스푼|티스푼)\s*씩?|"
        r"(?:두세|몇|여러)\s*(?:알|정|개)\s*더|한\s*움큼|한\s*줌|한\s*통\s*(?:을\s*)?(?:다|전부)|"
        r"정량\s*(?:무시|초과|넘)|다량|과량)[^.\n]{0,12}?(?:복용|드세요|드시|드셔|먹|섭취|삼키)"),
     Severity.HIGH, "overdose"),
    # 동일/동계열 중복 복용(아세트아미노펜·NSAID) — 간손상·위장출혈 사례.
    # (A) 연결어(함께/이어서/순차)로 두 약을 잇는 경우. 순차 연결어를 보강해
    #     '복용한 후 … 게보린도', '타이레놀로 시작해 … 게보린을 더하면' 우회를 막는다.
    # (B) 한 문장에 _DUP_DRUGS 가 둘 등장 + 추천 앵커(시너지/조합/완벽/두 배/더 효과)인
    #     마케팅 카피 — 명령형 동사 없이 권장하는 프레이밍. 두 약 동시 등장으로 게이팅돼
    #     단일 약 정상 언급은 발화하지 않는다(recall-safe).
    (re.compile(
        rf"(?:{_DUP_DRUGS})[^.\n]{{0,18}}?"
        r"(?:함께|같이|동시|추가로|또|번갈아|이어서|연달아|먹고\s*나서|뒤에|바로|"
        r"복용(?:한|하고)?\s*(?:후|뒤|다음)|로\s*시작(?:해|하여)|에\s*(?:이어|더해|더하면))"
        rf"[^.\n]{{0,18}}?"
        rf"(?:{_DUP_DRUGS}|진통제|해열제|소염제|감기약|복용|드세요|드셔|드시|먹|하나\s*더)|"
        rf"(?:{_DUP_DRUGS})[^.\n]{{0,28}}?(?:{_DUP_DRUGS})[^.\n]{{0,20}}?"
        r"(?:시너지|조합|완벽|두\s*배|더\s*효과)"),
     Severity.HIGH, "drug_duplication"),
    # 술 + 약물 병용 권장(호흡억제·간독성)
    (re.compile(
        rf"(?:{_ALCOHOL})[^.\n]{{0,15}}?(?:{_RX})[^.\n]{{0,14}}?"
        r"(?:같이|함께|곁들|드세요|드셔도|복용|괜찮)|"
        rf"(?:{_RX})[^.\n]{{0,15}}?(?:{_ALCOHOL})[^.\n]{{0,14}}?"
        r"(?:같이|함께|곁들|드세요|드셔도|괜찮)"),
     Severity.HIGH, "drug_alcohol_interaction"),
    # 자몽 + 약물 병용 권장(혈중농도 상승). 클래스명(_RX)뿐 아니라 스타틴 성분명(_STATIN)도
    # 받아 '심바스타틴+자몽' 성분명 카피 우회를 막는다(MAOI 로스터 방식 미러). 어순 양방향.
    # benign '자몽주스를 아침에 마셨다'(약물 엔티티 없음)는 미발화.
    (re.compile(
        rf"자몽[^.\n]{{0,15}}?(?:{_RX}|{_STATIN})[^.\n]{{0,12}}?(?:같이|함께|드세요|복용|괜찮|흡수)|"
        rf"(?:{_RX}|{_STATIN})[^.\n]{{0,15}}?자몽[^.\n]{{0,12}}?(?:같이|함께|드세요|드시|복용|괜찮|흡수|효과)"),
     Severity.HIGH, "grapefruit_interaction"),
    # 항응고 중복(와파린/아스피린 + 오메가3·은행잎·비타민E) — 출혈 위험.
    # 권고 앵커에 추천 명사(시너지/조합/완벽)를 추가 — 카피라이팅 프레이밍은 동사를
    # 생략한다('와파린, 오메가3, 아스피린, 완벽한 시너지!'). 엔티티 페어 게이팅으로 FP 억제.
    (re.compile(
        r"(?:와파린|항응고제)[^.\n]{0,18}?"
        r"(?:오메가\s*3?|은행잎?|비타민\s*E|아스피린|항응고)[^.\n]{0,12}?"
        r"(?:같이|함께|드세요|복용|마음껏|괜찮|시너지|조합|완벽)"),
     Severity.HIGH, "anticoagulant_interaction"),
    # 다약제 병용(5종 이상 한꺼번에) — polypharmacy 신기능 위험
    (re.compile(
        r"(?:약|영양제|보충제|제품|성분)\s*(?:\d+|다섯|여섯|일곱|여덟|아홉|열)\s*"
        r"(?:종|가지|개)\s*(?:이상|넘게|넘는)?[^.\n]{0,14}?"
        r"(?:한꺼번에|한\s*번에|동시|같이|모두|다)[^.\n]{0,10}?"
        r"(?:드세요|드셔도|복용|먹|괜찮|문제\s*없)"),
     Severity.HIGH, "polypharmacy"),
    # 오피오이드 + 벤조/Z-drug 병용 권장 — 중추신경 억제 중복(호흡억제·사망). 어순
    # 양방향, 병용 단서(함께/같이/병용/동시) + 투여 동사로 게이팅. 단독 처방·'병용하지
    # 마세요'(경고)는 두 약 동시 등장이 없거나 _has_genuine_warning 으로 억제돼 FP 없음.
    (re.compile(
        rf"(?:{_OPIOID})[^.\n]{{0,20}}?(?:{_BENZO})[^.\n]{{0,20}}?"
        r"(?:함께|같이|병용|동시|복용|드세요|드셔|드시|먹)|"
        rf"(?:{_BENZO})[^.\n]{{0,20}}?(?:{_OPIOID})[^.\n]{{0,20}}?"
        r"(?:함께|같이|병용|동시|복용|드세요|드셔|드시|먹)"),
     Severity.HIGH, "opioid_benzo_interaction"),
    # 칼륨 보충제 + ACE/ARB·칼륨보존 이뇨제 병용 권장 — 고칼륨혈증(부정맥). 두 엔티티
    # 동시 등장 + 추천/병용 앵커로 게이팅. '바나나는 칼륨이 풍부'(약물 엔티티 없음)는 미발화.
    (re.compile(
        rf"(?:{_POTASSIUM})[^.\n]{{0,20}}?(?:{_K_RAISING_RX})[^.\n]{{0,16}}?"
        rf"(?:{_ENDORSE}|채워|보충)|"
        rf"(?:{_K_RAISING_RX})[^.\n]{{0,20}}?(?:{_POTASSIUM})[^.\n]{{0,16}}?"
        rf"(?:{_ENDORSE}|채워|보충)"),
     Severity.HIGH, "hyperkalemia_interaction"),
    # 가짜 만병통치(false-cure) — 명명 엔티티(차가버섯/살구씨B17/베이킹소다/콜로이달실버/
    # 이버멕틴/콜로이드 은/게르손/붕사 등) + 완치·항암대안·코로나치료 주장 + 섭취/용량 단서.
    # 세 신호 동시 게이팅으로 '차가버섯은 식품입니다'(주장·용량 없음) 같은 benign 은 미발화.
    (re.compile(
        rf"(?:{_FALSE_CURE})[^.\n]{{0,30}}?(?:{_CURE_CLAIM})|"
        rf"(?:{_CURE_CLAIM})[^.\n]{{0,30}}?(?:{_FALSE_CURE})"),
     Severity.HIGH, "false_cure"),
    # 디곡신 + 루프/티아지드 이뇨제·CCB 병용 권장 — 저칼륨·농도상승으로 부정맥·중독.
    # DUR 쌍에 없어 전용 룰로. 두 엔티티 동시 등장 + _ENDORSE/병용 앵커로 게이팅 →
    # '디곡신은 심부전에 쓰입니다'(페어·앵커 없음)는 미발화(recall-safe). 어순 양방향.
    (re.compile(
        rf"(?:{_DIGOXIN})[^.\n]{{0,22}}?(?:{_DIGOXIN_PARTNER})[^.\n]{{0,18}}?(?:{_ENDORSE})|"
        rf"(?:{_DIGOXIN_PARTNER})[^.\n]{{0,22}}?(?:{_DIGOXIN})[^.\n]{{0,18}}?(?:{_ENDORSE})"),
     Severity.HIGH, "digoxin_interaction"),
    # 세로토닌 증후군 — 트립탄(편두통) + SSRI/SNRI/MAOI 병용 권장. 둘 다 세로토닌 작용을
    # 키워 고열·경련·사망. 성분 로스터 페어 + 병용/_ENDORSE 앵커로 게이팅 → 단일 트립탄
    # 복용 안내('수마트립탄은 하루 한 알')는 미발화(recall-safe). 어순 양방향.
    (re.compile(
        rf"(?:{_TRIPTAN})[^.\n]{{0,22}}?(?:{_SEROTONERGIC}|{_MAOI})[^.\n]{{0,18}}?"
        rf"(?:{_ENDORSE})|"
        rf"(?:{_SEROTONERGIC}|{_MAOI})[^.\n]{{0,22}}?(?:{_TRIPTAN})[^.\n]{{0,18}}?"
        rf"(?:{_ENDORSE})"),
     Severity.HIGH, "serotonin_syndrome"),
    # 시메티딘(CYP 억제) + 와파린/항응고 병용 권장 — 항응고 효과 증대로 출혈 위험.
    # 두 엔티티 동시 등장 + 병용/_ENDORSE 앵커. 어순 양방향. 단일 언급은 미발화.
    (re.compile(
        rf"(?:{_CIMETIDINE})[^.\n]{{0,22}}?(?:와파린|항응고제?)[^.\n]{{0,18}}?(?:{_ENDORSE})|"
        rf"(?:와파린|항응고제?)[^.\n]{{0,22}}?(?:{_CIMETIDINE})[^.\n]{{0,18}}?(?:{_ENDORSE})"),
     Severity.HIGH, "cimetidine_interaction"),
    # 메트포르민 + 조영제(요오드) — 검사 시 일시 중단해야 하는데 '계속 복용/그대로'를
    # 권하면 신장·젖산산증 위험. '계속/그대로/중단 없이' 같은 continue-despite 앵커 필요 →
    # '메트포르민은 당뇨약입니다'(조영제·계속 앵커 없음)는 미발화. 어순 양방향.
    (re.compile(
        r"메트포르민[^.\n]{0,24}?(?:조영제|요오드|CT\s*조영|조영\s*검사)[^.\n]{0,18}?"
        r"(?:계속|그대로|중단\s*없이|당일에?도|복용하세요|드세요|괜찮)|"
        r"(?:조영제|요오드|CT\s*조영|조영\s*검사)[^.\n]{0,24}?메트포르민[^.\n]{0,18}?"
        r"(?:계속|그대로|중단\s*없이|복용하세요|드세요|괜찮)"),
     Severity.HIGH, "metformin_contrast_interaction"),
    # 알로푸리놀 + 아자티오프린 병용 권장 — 골수억제(치명적 혈구감소). 둘 다 DUR ingredient
    # 이나 공식 쌍에 누락돼 _scan_dur 가 못 잡으므로 전용 룰. 병용/_ENDORSE 앵커, 어순 양방향.
    (re.compile(
        rf"(?:알로푸리놀|allopurinol)[^.\n]{{0,22}}?(?:아자티오프린|azathioprine|"
        rf"머캅토퓨린|6-MP)[^.\n]{{0,18}}?(?:{_ENDORSE})|"
        rf"(?:아자티오프린|azathioprine|머캅토퓨린|6-MP)[^.\n]{{0,22}}?"
        rf"(?:알로푸리놀|allopurinol)[^.\n]{{0,18}}?(?:{_ENDORSE})"),
     Severity.HIGH, "allopurinol_azathioprine_interaction"),
    # 백신 미신(vaccine misinformation) — ① (백신/예방접종) + (자폐/자폐증) 인과 주장
    # 동시 등장, 또는 ② (백신/예방접종) + 거부·접종 만류('접종하지 마/맞지 마/거부/믿지
    # 마') 권고. 두 신호 게이팅으로 benign('백신 부작용 상담은 의료진과', '백신 접종 후
    # 발열은 흔한 반응')은 미발화(recall-safe). 어순 양방향.
    (re.compile(
        r"(?:백신|예방\s*접종|vaccine)[^.\n]{0,30}?(?:자폐(?:증|스펙트럼)?|autism)|"
        r"(?:자폐(?:증|스펙트럼)?|autism)[^.\n]{0,30}?(?:백신|예방\s*접종|vaccine)|"
        r"(?:백신|예방\s*접종|주사|접종)[^.\n]{0,24}?"
        r"(?:접종하지\s*마|맞지\s*마|맞히지\s*마|거부(?:하세요|하십|해야|하라)?|"
        r"믿지\s*마|시키지\s*마|하지\s*마세요|위험하니\s*피)"),
     Severity.HIGH, "vaccine_misinformation"),
    # 소아에게 성인 용량/약 그대로 — 생애주기(영유아) 과량 위험. '절반/줄여'는 매칭 안 됨.
    # (A) child-noun + '어른/성인 (용량|약|것|타이레놀…)\s*(그대로|만큼|동일|똑같)' + 투여.
    #     '용량' 단어 외에 약·것·약품명도 받아 '어른 타이레놀을 그대로' 우회를 잡는다.
    # (B) fallback: child-noun 없이도 '어른/성인 (용량|약|것) 그대로 … 먹이/먹여'(사동) —
    #     '먹이/먹여' 사동이 아이에게 먹이는 행위를 함의하므로 child-noun 미요구.
    #     benign '성인은 1정 그대로 복용'은 사동(먹이/먹여)이 아니라 미발화(recall-safe).
    (re.compile(
        r"(?:아이|아기|소아|유아|어린이|영유아|애기)[^.\n]{0,20}?"
        r"(?:어른|성인)\s*(?:용량|약|것|타이레놀|약품|약물)?[^.\n]{0,4}?(?:그대로|만큼|동일|똑같)[^.\n]{0,12}?"
        r"(?:먹이|먹여|드세요|드시|복용|줘|주세요|먹)|"
        r"(?:어른|성인)\s*(?:용량|약|것)\s*그대로[^.\n]{0,10}?(?:먹이|먹여)"),
     Severity.HIGH, "pediatric_overdose"),
    # 소아에게 향정신성·진정 약물을 몰래/갈아/타서 투여 — 아동 대상 약물 위해.
    # 정상 소아 투약('처방대로/시럽으로 먹이세요')과 구분하려고: ① 진정·향정 계열 약물 +
    # ② 은닉/진정 목적 단서(갈아/몰래/타서/섞어/재우려고)가 *둘 다* 같은 문장에 있고
    # ③ 투여 동사가 있을 때만 잡는다. 어순(아이↔약물↔은닉 동사)에 무관하도록 양방향.
    (re.compile(
        # (A) 아이 … 약물 … 은닉/진정 … 투여
        r"(?:아이|아기|소아|유아|어린이|영유아|애기|애)[^.\n]{0,28}?"
        rf"(?:{_CHILD_HARM_DRUG})[^.\n]{{0,24}}?(?:{_COVERT})[^.\n]{{0,16}}?(?:{_ADMIN})|"
        # (B) 아이 … 은닉/진정 … 약물 … 투여
        r"(?:아이|아기|소아|유아|어린이|영유아|애기|애)[^.\n]{0,28}?"
        rf"(?:{_COVERT})[^.\n]{{0,16}}?(?:{_CHILD_HARM_DRUG})[^.\n]{{0,16}}?(?:{_ADMIN})|"
        # (C) 약물 … 은닉/진정 … 아이 … 투여 (약물이 문두)
        rf"(?:{_CHILD_HARM_DRUG})[^.\n]{{0,18}}?(?:{_COVERT})[^.\n]{{0,14}}?"
        r"(?:아이|아기|소아|유아|어린이|영유아|애기|애)[^.\n]{0,16}?"
        rf"(?:{_ADMIN})|"
        # (D) 은닉/진정 … 약물 … 아이 … 투여
        rf"(?:{_COVERT})[^.\n]{{0,14}}?(?:{_CHILD_HARM_DRUG})[^.\n]{{0,14}}?"
        r"(?:아이|아기|소아|유아|어린이|영유아|애기|애)[^.\n]{0,16}?"
        rf"(?:{_ADMIN})|"
        # (E) 약물 … 아이 … 은닉/진정 … 투여 (약물 문두 + 아이 중간)
        rf"(?:{_CHILD_HARM_DRUG})[^.\n]{{0,12}}?"
        r"(?:아이|아기|소아|유아|어린이|영유아|애기|애)[^.\n]{0,18}?"
        rf"(?:{_COVERT})[^.\n]{{0,14}}?(?:{_ADMIN})"),
     Severity.HIGH, "child_medication_harm"),
    # 약물-식품 상호작용(자몽/포도/석류/우유/치즈 — DUR 병용금기 밖이나 위험)
    # MAOI 는 클래스명(MAO/마오)만으로는 마케팅 카피('페넬진 곁들여 드세요')를 못 잡으므로
    # 실제 성분 로스터(KO+EN)로 트리거한다. 권고 앵커에 명령형 동사뿐 아니라 긍정-추천
    # 명사(시너지/조합/완벽/마음껏/즐기/추천)도 받는다 — 카피라이팅은 동사를 흔히 생략한다.
    (re.compile(
        rf"(?:{_MAOI})[^.\n]{{0,18}}?(?:치즈|와인|발효|숙성)[^.\n]{{0,14}}?(?:{_ENDORSE})|"
        rf"(?:치즈|와인|발효|숙성)[^.\n]{{0,18}}?(?:{_MAOI})[^.\n]{{0,14}}?(?:{_ENDORSE})|"
        r"테트라사이클린[^.\n]{0,12}?우유|우유[^.\n]{0,10}?테트라사이클린|"
        r"(?:혈압약|콜레스테롤약|약)[^.\n]{0,10}?(?:자몽|포도\s*주스?|석류)[^.\n]{0,15}?"
        r"(?:같이|흡수|효과|곁들|드세요|드시)"),
     Severity.HIGH, "drug_food_interaction"),
    # 필수약/필수치료 임의 중단 권유(인슐린/혈압약/항암치료 등) — 자의 중단은 위험.
    # 항암·화학·방사선·면역항암·표적 치료를 로스터에 추가(가짜 '대안 치료' 권유에서
    # '항암치료…당장 중단/멈추어도 괜찮' 패턴 발화). 중단 동사도 '멈추어도/멈춰도 괜찮'을
    # 추가하되 기존 동사는 보존한다(recall-safe). 진짜 경고('의료진과 상의')는
    # _has_genuine_warning 으로 별도 억제.
    (re.compile(
        r"(?:인슐린|혈압약|항경련제|갑상선약|면역억제제|항응고제|결핵약|"
        r"항생제|항우울제|정신과\s*약|렉사프로|"
        r"항암(?:치료|제)?|화학(?:요법|치료)|방사선\s*치료|면역항암|표적\s*치료)[^.\n]{0,28}?"
        r"(?:끊고|끊으|중단|그만\s*드|그만\s*두|멈추(?:어도|면|고)|멈춰도|"
        r"안\s*드셔도\s*(?:돼|된|좋)|"
        # R4 보강: 부드러운 중단 권유('드실 필요(가)? 없', '안 드셔도', '약을 내려놓',
        # '복용을 멈추', '버리') — 기존 동사는 보존하고 alternation 만 추가(recall-safe).
        r"드실?\s*필요(?:가|는)?\s*없|드시지\s*않아도|내려놓|복용을?\s*멈추|"
        r"즉시\s*중단|바로\s*끊|버리(?:세요|십|시)|복용\s*중단)"),
     Severity.HIGH, "essential_drug_discontinuation"),
    # 독버섯/야생 섭취 권장
    (re.compile(r"(?:야생|들|산에서\s*캔|이름\s*모르는)\s*버섯[^.\n]{0,15}?"
                r"(?:드세요|드시|먹어도|먹(?:으면\s*)?(?:돼|된다|좋)|식용|안전)"),
     Severity.HIGH, "wild_foraging"),
    # 자연 독소 식품/약초 가정 조리·섭취 권장(복어/컴프리) — 조리·섭취 동사로 게이팅.
    (re.compile(rf"(?:{_TOXIC_FOOD})[^.\n]{{0,24}}?(?:{_TOXIC_FOOD_VERB})"),
     Severity.HIGH, "toxic_food"),
    # 생간·생고기 회 raw 섭취 권장 — 섭취 동사 직전에 가열·조리 동사가 없을 때만(익혀
    # 드세요 같은 안전 권고 제외). 부정 lookbehind 없이 짧은 고정폭 차단어로 구현.
    (re.compile(rf"(?:{_RAW_MEAT})(?![^.\n]{{0,18}}?(?:익혀|익혀서|가열|끓여|조리해|구워))"
                rf"[^.\n]{{0,18}}?(?:회로|드세요|드시|먹|마시|섭취|즐기)"),
     Severity.HIGH, "raw_meat"),
    # 물 중독(water intoxication) — 단시간 대량 수분을 *몰아서/한 번에* 섭취하라는 지시.
    # 저나트륨혈증 위험. 정상 권고('물 자주/충분히 드세요', '하루 2리터 나눠 드세요')는
    # 1.5리터+ 대량 + 몰아/한꺼번에/한 번에 같은 burst 어휘가 없어 매칭되지 않는다(recall-safe).
    # 어순 양방향: (물 … 대량 … 몰아) / (대량 … 몰아 … 물).
    (re.compile(
        r"(?:물|수분|생수)[^.\n]{0,20}?"
        r"(?:[2-9]\s*리터|\d{2,}\s*리터|1\.5\s*리터|[2-9]\s*ℓ|"
        r"[1-9]\s*,?\s*\d{3}\s*(?:ml|㎖|밀리|cc)|[2-9]\s*000\s*(?:ml|㎖|cc))"
        r"[^.\n]{0,24}?(?:몰아|한꺼번에|한\s*번에|한\s*방에|벌컥|단숨에|들이키|들이부)|"
        r"(?:[2-9]\s*리터|\d{2,}\s*리터|1\.5\s*리터|"
        r"[1-9]\s*,?\s*\d{3}\s*(?:ml|㎖|밀리|cc)|[2-9]\s*000\s*(?:ml|㎖|cc))"
        r"[^.\n]{0,12}?(?:물|수분|생수)[^.\n]{0,20}?"
        r"(?:몰아|한꺼번에|한\s*번에|한\s*방에|벌컥|단숨에|들이키|들이부)"),
     Severity.HIGH, "water_intoxication"),
]


def _v_dur(code: str, reason: str, matched: str) -> Violation:
    return Violation(code=code, category=Category.UNSAFE_ADVICE,
                     severity=Severity.HIGH, reason=reason, matched=matched[:60])


def _scan_dur_sentence(sentence: str) -> list[Violation]:
    """한 문장에 대한 DUR 판정. 경고 구조(부정 아닌)면 제외. 성분명 동시 등장 + 권고 동사."""
    if _has_genuine_warning(sentence) or not _DUR_REC.search(sentence):
        return []
    found = sorted(set(_DUR_INGR_RE.findall(sentence)))
    if not found:
        return []
    for i, a in enumerate(found):
        for b in found[i + 1:]:
            if frozenset({a, b}) in _DUR_PAIRS:
                return [_v_dur("dur_interaction", f"DUR 병용금기 성분: {a}+{b}", f"{a}+{b}")]
    if re.search(r"임[산부신]|임신|모유\s*수유", sentence):
        for ing in found:
            if ing in _DUR_PREG:
                return [_v_dur("dur_pregnancy", f"DUR 임부금기 성분: {ing}", ing)]
    if re.search(r"소아|어린이|영유아|유아|아기|애기", sentence):
        for ing in found:
            if ing in _DUR_AGE:
                return [_v_dur("dur_age", f"DUR 연령금기 성분: {ing}", ing)]
    return []


def _scan_dur(text: str) -> list[Violation]:
    """DUR 공식 데이터 기반 — 병용금기 성분쌍/임부금기/연령금기 성분 + 권고 동사면 위험.
    경고 억제는 *같은 문장* 범위로 제한한다(OG-9) — 다른 문장의 무관한 경고('와파린은
    주의')가 위험 권고가 든 문장의 판정을 무력화하면 안 되므로 문장 단위로 본다."""
    out: list[Violation] = []
    for sentence in re.split(r"[.!?\n]", text):
        out += _scan_dur_sentence(sentence)
    return out


def scan_unsafe_advice(text: str) -> list[Violation]:
    out: list[Violation] = []
    # 같은 문장에 여러 매칭이 떨어지면 _has_genuine_warning 을 매칭마다 재실행해 O(n^2)
    # 가 된다(반복 엔티티 입력). 문장 (left,right) 경계로 경고 판정을 메모이즈해 문장당
    # 1회만 평가한다 — 의미는 동일(같은 문장 → 같은 경고 여부), 순수 성능 최적화.
    warn_cache: dict[tuple[int, int], bool] = {}
    for pat, sev, code in _PATTERNS:
        for m in pat.finditer(text):
            bounds = _sentence_bounds(text, m.start(), m.end())
            warned = warn_cache.get(bounds)
            if warned is None:
                warned = _has_genuine_warning(text[bounds[0]:bounds[1]])
                warn_cache[bounds] = warned
            if warned:
                continue  # 같은 문장에 (부정 아닌) 안전 경고 → 위험 권장 아님
            out.append(
                Violation(
                    code=code,
                    category=Category.UNSAFE_ADVICE,
                    severity=sev,
                    reason=f"potentially dangerous recommendation: {code}",
                    start=m.start(),
                    end=m.end(),
                    matched=m.group(0)[:60],
                )
            )
    out += _scan_dur(text)
    return out
