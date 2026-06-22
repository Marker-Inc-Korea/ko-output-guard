"""자해/자살 방법 안내 탐지 — LLM 출력이 자해·자살의 *방법*을 제공하거나 부추기면 BLOCK.

위해 정보를 막는 게 목적이므로 잡는 건 "방법 제시/조장"이다. 위기 개입 자원 안내
(자살예방상담 1393, 정신건강상담 1577-0199, 병원·전문가 권유)는 보호 메시지이므로
반드시 SAFE 로 둔다 — help-context 문장은 룰에서 제외한다(과탐 방지).
"""
from __future__ import annotations

import re

from ..result import Category, Severity, Violation

# 위기 개입/도움 안내 문맥 — 같은 문장에 있으면 '방법 제시'가 아니라 '보호 메시지'다.
# 1393(자살예방), 1577-0199(정신건강), 129(보건복지), 생명의전화 등 공식 자원 포함.
_HELP_CTX = re.compile(
    r"자살\s*예방|예방\s*상담|상담\s*(?:전화|센터|받|하|을|를)|생명의\s*전화|"
    r"정신\s*건강|핫라인|전문가|전문의|정신과|병원|치료|도움\s*(?:을|받|청|요청)|"
    r"혼자\s*가 아니|곁에\s*있|버티|힘내|괜찮아질|희망|손\s*내밀|위기\s*상담|"
    r"1393|109|1577-?0199|129|1588-?9191|상담\s*1393|마음\s*(?:이|을)\s*나누|털어놓")

# 경고/만류 문맥 — '하지 마세요/그러면 안 됩니다'식은 방법 제시가 아니다. OG-1: bare
# '위험' 한 단어가 끝에 붙었다고 자해 방법 제시를 무력화하면('번개탄을 피우면 됩니다
# 위험해요') 우회된다. 그래서 '위험'은 *금지·만류에 결합된 형태*(위험하니/위험하므로 등
# 인과 연결, 또는 하지 마/마세요 와 같은 금지 구조)일 때만 만류로 본다. bare 위험은 X.
_DISCOURAGE = re.compile(
    r"하지\s*마|마세요|안\s*됩니다|안\s*돼|절대\s*(?:안|하지)|"
    # '멈추'는 만류 명령형(멈추세요/멈춰/멈추자)만 만류로 본다 — 완곡 자살어 '심박수를
    # 멈추기'의 '멈추'가 만류로 오인돼 lethal 매칭을 무력화하던 충돌을 막는다.
    r"그만\s*두|멈춰|멈추(?:세요|십|시|어\s*요|자|길|는\s*게|지\s*마)|"
    r"소중|함께\s*이겨|이겨\s*내|살\s*수\s*있|살아|"
    # '위험'은 결과·만류로 결합된 형태만(인과 연결어미 …니/…므로/…어 + 만류문맥).
    r"위험하(?:니|므로|여|니까|기\s*때문)")
# OG-8: 만류어 직후 부정(않/없/아니)이면 '위험하지 않으니 해보세요'식 *역-만류*라 보호
# 메시지가 아니다. unsafe_advice/weapons 와 동일한 negation-after 가드를 self_harm 에도 둔다.
_NEG_AFTER = re.compile(r"하지\s*않|지\s*않|없|아니")


def _is_protective(sentence: str) -> bool:
    """문장이 위기개입(도움 안내) 또는 *부정으로 무너지지 않은* 만류면 보호 메시지."""
    if _HELP_CTX.search(sentence):
        return True
    for m in _DISCOURAGE.finditer(sentence):
        if not _NEG_AFTER.search(sentence[m.end():m.end() + 8]):
            return True
    return False

# 자해/자살 동작·대상 어휘. 의료·뉴스 맥락의 단순 언급이 아니라 *방법/실행 안내*를 잡는다.
_SELFHARM = (
    r"죽는\s*(?:법|방법|약|가장\s*좋)|"               # '고통 없이 죽는 법'
    r"(?:자살|극단적\s*선택)\s*(?:하는\s*)?(?:법|방법|도구|약|수단)|"
    r"고통\s*없이\s*(?:죽|가|세상을\s*떠|숨)|"
    r"목(?:을|\s*)?\s*(?:매|메)(?:는|달|어|도|서|면|세요|봐|보|자|지)|목\s*매달|"  # 교사
    # 교사(목맴) 명사형 — 자해 특이적 어휘 '목맴'만 단독 anchor(직후 6자 안에 역사·판결 등
    # 제도 서술이 오면 제외 → recall-safe). '교수형'은 사형 제도의 법률 용어이기도 해 단독
    # 으론 잡지 않고, 기전(목/밧줄/발판) 또는 EN 'hanging' co-anchor 와 함께일 때만 아래
    # 근접 스캐너에서 본다(역사·판결 산문 FP 방지).
    r"목맴(?!.{0,6}(?:역사|판결|집행|선고|형장|제도))|"
    # 손목/동맥 자상 — 베다·긋다 외에 '절단/자르/잘라'(영문 amputation 번역체) 동사도 잡는다.
    # 손목+동맥 self-context 에서 '절단'은 임상 절단술과 공기(共起)가 사실상 없어 recall-safe.
    r"손목\s*(?:을\s*)?(?:긋|그어|베|절단|자르|잘라)|동맥\s*(?:을\s*)?(?:긋|끊|절단|자르|잘라)|"
    r"높은\s*(?:곳|데|건물|곳에서)\s*(?:에서\s*)?뛰어내리|투신|"  # 추락
    r"번개탄(?:을|\s)*\s*(?:피우|태우|준비)|연탄(?:을|\s)*\s*(?:피우|가스)|"  # 일산화탄소
    # 비닐봉지/봉투 질식(plastic-bag suffocation)은 윈도가 넓어 _BAG_SUFFOCATION 으로 따로
    # 본다(아래) — 머리-신호와 밀폐-신호가 여러 문장에 흩어지므로 질식 anchor 와 함께 봐야
    # recall-safe('비닐봉지를 머리에 쓰고 뛰어가곤 했다' 같은 일상 묘사 FP 방지).
    # 일산화탄소(숯·숯덩이·화로). BBQ·난방 정상용은 _COOKING_CTX, 뉴스/사고 보도는
    # _ACCIDENT_CTX 로 별도 억제(아래). '연탄가스'는 사고 보도에 흔해 단독 매칭은 제외.
    r"(?:숯덩이|숯불|숯|연탄)[^.\n]{0,24}?(?:화로|피우|태우|연소|밀폐(?:된|한)?\s*(?:방|공간|차))|"
    r"화로[^.\n]{0,16}?(?:숯덩이|숯불|숯|연탄|피우|태우|연소)|"
    r"약(?:을)?\s*(?:한\s*움큼|한\s*통|다량|모아|모두)\s*(?:먹고|삼키|복용해\s*죽)|"
    # '치사량'은 약리·독성시험 서술(마우스/랫드 LD50, 'mg/kg 용량은 치사량이었고')에 흔하므로
    # 사람의 섭취 동사가 근접할 때만 자해로 본다(비임상 독성 데이터 FP 방지).
    r"치사량(?:을|의|만큼|이상)?[^.\n]{0,18}?(?:먹|복용|삼키|삼켜|섭취|마시|들이키)|"
    r"치명적인\s*(?:양|용량)\s*(?:으로|을\s*먹|복용)"
)

# 안락사형 우회 — 특정 약물(진정·수면·항말라리아 등)에 *치사 의도 완곡어*가 결합된 표현.
# '디아제팜 100mg … 존재의 종말', '클로로퀸 정제 … 심박수를 멈추기 직전' 처럼 약물+mg/정제 +
# 죽음 완곡어가 같은 윈도에 있으면 복용 지시 동사가 없어도 자살 안내로 본다. 정상 처방
# 설명('디아제팜 5mg 1정 식후 복용')은 죽음 완곡어가 없어 매칭되지 않는다(recall-safe).
_LETHAL_DRUG = (
    r"클로로퀸|하이드록시클로로퀸|디아제팜|로라제팜|알프라졸람|졸피뎀|졸피드|페노바르비탈|"
    r"바르비탈|아미트립틸린|모르핀|펜타닐|옥시코돈|청산가리|시안화|니코틴\s*원액|"
    # 브랜드·은어(자낙스=알프라졸람, 벤조=벤조디아제핀, 아티반=로라제팜, 렉사프로=항우울제).
    # _LETHAL 은 약물+용량+완곡어/과량동작 공기를 요구하므로 브랜드 추가도 recall-safe.
    r"자낙스|벤조디아제핀|벤조|아티반|렉사프로|"
    # R3: 졸피뎀 브랜드/은어(스틸녹스=Stilnox, 암비엔=Ambien, 이미다). 졸피뎀 generic 은
    # 이미 있으나 브랜드명은 누락 — _LETHAL 은 약물+용량+(완곡어|과량동작) 공기를 요구하므로
    # 브랜드 추가도 recall-safe('스틸녹스 처방받아 보관 중'은 용량·완곡어 없어 SAFE).
    r"스틸녹스|스틸록스|Stilnox|암비엔|Ambien|이미다|"
    r"수면제|진정제|신경안정제|항우울제|아세트아미노펜|타이레놀"
)
_LETHAL_EUPHEMISM = (
    r"심(?:장|박|박수)[^.\n]{0,8}?멈추|존재[^.\n]{0,6}?종말|영원히\s*잠(?:들|이)|"
    r"영원한\s*(?:잠|안식|평화|고요|해방|안락)|생(?:을|를)?\s*마감|돌아오지\s*않|"
    r"다시\s*깨어나지\s*(?:않|못)|다시는?\s*깨(?:지|어나지)\s*(?:않|못)|끝없는\s*잠|"
    r"완벽(?:하고)?\s*조용한\s*(?:결론|끝)|별이\s*되어\s*(?:흩|사라)|"
    # R3: 약물 과량 서사 완곡어 — '마지막 관문', '무중력…가라앉'(존재의 종말 류).
    r"마지막\s*관문|무중력[^.\n]{0,8}?가라앉|"
    r"끝(?:을|낼)\s*수\s*있는\s*(?:양|용량)|편안한\s*(?:죽음|끝|마지막)|세상과\s*작별|숨(?:이|을)?\s*멎"
)
_DRUG_DOSE = (
    r"(?:\d+\s*(?:mg|밀리그램|그램|g)|정제|농축액|캡슐|알약|"
    r"한\s*통|[두세]\s*통|여러\s*통|한\s*봉지|충분한\s*양|치사량)"
)
# 과량 복용 동작 — '털어 넣/쏟아부/입안에 …' 처럼 한 번에 들이켜는 행위. 약물+용량과
# 같은 윈도에 있으면 죽음 완곡어가 없어도 과다복용 안내로 본다(브랜드/은어 우회 대응).
# 정상 처방·구매 라인('자낙스 한 통 처방받아')은 이 과량동작이 없어 매칭되지 않는다.
_OVERDOSE_ACTION = (
    r"털어\s*넣|털어넣|입(?:안|속)(?:으로|에)?\s*(?:털|쏟|들이|밀어)|"
    # R3: '쥐고…삼키'(알약을 쥐었다가 삼키는 과량 서사). 약물+용량과 같은 줄에 있을 때만
    # 발화하므로 일상 '손에 쥐고'(약물 없음)는 영향 없음(recall-safe).
    r"쥐고[^.\n]{0,12}?삼키|쥐었[^.\n]{0,12}?삼키|"
    r"쏟아\s*부|한꺼번에\s*(?:삼키|먹|들이)|들이켜|꿀꺽\s*삼키")

# 자해/자살을 *부추기는* 권유형 표현(방법 어휘가 약해도 조장 자체가 위험).
_ENCOURAGE = re.compile(
    r"(?:자살|극단적\s*선택|죽어\s*버리|죽는\s*게|사라지는\s*게)[^.\n]{0,16}?"
    r"(?:하세요|하는\s*게\s*(?:나|낫|좋)|편해|답이|방법이|어때|권|추천|차라리)|"
    r"(?:차라리|그냥)\s*죽")

# 비닐봉지 질식(plastic-bag suffocation). 실제 자살 묘사는 봉지·머리/밀폐·질식 신호가
# 여러 문장에 흩어지므로(예: "봉지를 머리 위로 끌어올렸다. 입구를 밀폐했다. 숨 막힘의
# 의식.") 셋을 하나의 백트래킹 정규식으로 묶으면 ReDoS 가 난다. 그래서 세 신호를 *독립*
# 정규식으로 각각 찾고(선형), 같은 줄(\n 미포함) 안에서 ≤120자 근접일 때만 위반으로 본다.
# *질식 anchor*(숨막/질식/숨이 멎)를 반드시 요구해 일상 묘사('비닐봉지를 머리에 쓰고
# 뛰어가곤 했다')는 SAFE 로 둔다(recall-safe).
_BAG_RE = re.compile(r"비닐\s*봉지|비닐봉지|봉투|봉지")
_BAG_ACTION_RE = re.compile(
    r"(?:머리(?!\s*카락)|얼굴)\s*(?:위로|에)?\s*(?:쓰|쓴|뒤집어|끌어올|덮어|감싸|씌)|"
    r"밀폐|밀봉|단단히\s*(?:묶|조이|매|밀)|마감(?:된|한)?\s*입구")
_SUFFOCATE_RE = re.compile(
    r"숨\s*(?:막|이\s*막|을\s*막|쉴\s*수\s*없|멎|을\s*거두)|질식|호흡\s*(?:곤란|정지)|"
    # R3: '호흡을 멈', '의식을 잃' — 질식 결과 신호 추가(불활성가스/봉지 질식 공통).
    r"호흡(?:을)?\s*멈|의식을\s*잃")
_BAG_PROXIMITY = 120  # 세 신호가 모두 이 글자수 윈도 안(같은 줄)이면 질식 안내로 본다.


def _bag_suffocation_spans(text: str) -> list[tuple[int, int]]:
    """봉지·(머리/밀폐 동작)·질식 세 신호가 같은 줄 ≤120자 윈도에 모두 있으면 그 구간 반환.
    독립 search 3종을 줄 단위로 돌려 백트래킹 없이(선형) 근접만 확인한다(ReDoS-safe)."""
    spans: list[tuple[int, int]] = []
    base = 0
    for line in text.split("\n"):
        bags = [m.start() for m in _BAG_RE.finditer(line)]
        acts = [m.start() for m in _BAG_ACTION_RE.finditer(line)]
        sufs = [m.start() for m in _SUFFOCATE_RE.finditer(line)]
        if bags and acts and sufs:
            lo = min(bags + acts + sufs)
            hi = max(bags + acts + sufs)
            if hi - lo <= _BAG_PROXIMITY:
                spans.append((base + lo, base + min(hi + 4, len(line))))
        base += len(line) + 1  # +1 for the stripped '\n'
    return spans


def _proximity_spans(
    text: str, signals: tuple[re.Pattern[str], ...], window: int,
) -> list[tuple[int, int]]:
    """모든 signal 정규식이 같은 줄(\n 미포함) ≤window 글자 윈도에 *각각* 매칭되면 그 구간 반환.
    독립 search 를 줄 단위로 돌려(선형) 백트래킹 없이 근접만 확인한다(ReDoS-safe).
    _bag_suffocation_spans 의 일반화 — 익사·동사·교사·투신·교살 등 다신호 anchor 에 재사용."""
    spans: list[tuple[int, int]] = []
    base = 0
    for line in text.split("\n"):
        hits = [[m.start() for m in pat.finditer(line)] for pat in signals]
        if all(hits):
            flat = [p for group in hits for p in group]
            lo, hi = min(flat), max(flat)
            if hi - lo <= window:
                spans.append((base + lo, base + min(hi + 4, len(line))))
        base += len(line) + 1  # +1 for the stripped '\n'
    return spans


def _proximity_spans_clustered(
    text: str, signals: tuple[re.Pattern[str], ...], window: int,
) -> list[tuple[int, int]]:
    """_proximity_spans 와 같되 *가장 가까운 클러스터*만 본다 — 신호가 한 줄에 여러 번
    흩어져도(예: '… / …' 반복) 모든 신호가 폭 ≤window 안에 함께 존재하면 그 cluster 구간을
    반환한다. 전역 min/max(_proximity_spans)가 멀리 떨어진 중복 매칭 때문에 윈도를 넘겨
    놓치던 케이스를 보강한다.
    구현: 줄별로 모든 신호 매칭을 (위치, 신호번호)로 모아 정렬한 뒤 two-pointer 슬라이딩
    윈도로 '모든 신호가 폭 ≤window 안에 들어오는' 최초 구간을 찾는다. 각 이벤트가 윈도에
    한 번 들어오고 한 번 나가므로 줄 길이에 *선형* — 이전 pivot×group 방식의 O(n^2)
    단일-긴-줄 폭발을 제거한다(ReDoS·다항폭발 모두 없음)."""
    spans: list[tuple[int, int]] = []
    n_sig = len(signals)
    base = 0
    for line in text.split("\n"):
        events: list[tuple[int, int]] = []
        seen = 0
        for i, pat in enumerate(signals):
            found = False
            for m in pat.finditer(line):
                events.append((m.start(), i))
                found = True
            if found:
                seen += 1
        if n_sig and seen == n_sig:
            events.sort()
            counts: dict[int, int] = {}
            distinct = 0
            lo_idx = 0
            for hi_idx in range(len(events)):
                s_hi = events[hi_idx][1]
                if counts.get(s_hi, 0) == 0:
                    distinct += 1
                counts[s_hi] = counts.get(s_hi, 0) + 1
                # 윈도 폭(>window) 초과 시 왼쪽을 줄여 폭 ≤window 유지
                while events[hi_idx][0] - events[lo_idx][0] > window:
                    s_lo = events[lo_idx][1]
                    counts[s_lo] -= 1
                    if counts[s_lo] == 0:
                        distinct -= 1
                    lo_idx += 1
                if distinct == n_sig:
                    lo, hi = events[lo_idx][0], events[hi_idx][0]
                    spans.append((base + lo, base + min(hi + 4, len(line))))
                    break  # 줄당 한 cluster 면 BLOCK 충분
        base += len(line) + 1  # +1 for the stripped '\n'
    return spans


# ── 익사(drowning) ── 익사 anchor + *의도적 가라앉음* co-signal 을 같은 줄에서 요구한다.
# co-signal 은 자살 익사 특이 신호(가라앉도록/공기를 내쉬어 폐에 물/걸어 들어가 가라앉)로
# 한정 — 단순 무게어(돌·주머니)나 '깊은 물'만으론 부족하다(구조·사고 산문 FP 방지). 게다가
# 구조·구출 문맥(_DROWN_RESCUE)이 같은 줄이면 익사 묘사라도 억제(recall-safe).
_DROWN_ANCHOR = re.compile(
    r"익사|물에\s*빠|폐(?:에|\s*속(?:의|에)?)\s*[^.\n]{0,6}?물|기도(?:를|에)\s*물|"
    # R3: '호흡기…물'(narration) anchor 추가 — 호흡기로 물이 밀려 들어오는 익사 서사.
    r"호흡기[^.\n]{0,8}?물|"
    # R3: 溺水(CJK 음독·익사) anchor 추가 — 入水 옆. 한국어 양성 충돌 없는 CJK method 어휘.
    r"\bdrown(?:ing|ed)?\b|入水|溺水")
_DROWN_COSIGNAL = re.compile(
    r"가라앉(?:도록|기\s*위|히|아)|공기를\s*(?:내쉬|빼|모두\s*내)|물이\s*폐를\s*채우|"
    r"폐를\s*물로|숨을\s*참(?:고|아)|걸어\s*들어가|"
    # R3: CN→KO 번역체 동반 신호 — '익사하여 …'. cosignal 전용이라 anchor 없이는 발화 안 함.
    # 주의: '폐…물…가득/찼' 형태는 폐부종(의료) '폐에 물이 찼다'와 충돌(FP)하므로 cosignal 에서
    # 제외한다. CN→KO '폐에는 물이 가득' 서사는 같은 줄의 '걸어 들어가'·'익사' cosignal 로 잡힌다.
    r"익사(?:하|하여|해|로)|"
    r"(?:무거운\s*)?돌(?:들|멩이)?[^.\n]{0,12}?(?:주머니|채워|매달|묶)")
# 구조·구출·사고 보도 — 익사 묘사라도 '구했/구조/건졌/빠진 사람을' 등이면 자해 안내가 아니다.
_DROWN_RESCUE = re.compile(
    r"구조|구출|구했|구해|건져|건졌|구명|예방|살려|빠진\s*(?:사람|아이|이|분)")
_DROWN_WINDOW = 90

# ── 손목/동맥 자상(wrist/artery) ── 손목 또는 동맥 anchor + 절단/자르/긋 동사가 한 줄
# 근접이면 자상. '손목의 요골 동맥을 … 절단'처럼 anchor↔동사 사이에 수식어가 끼어도 잡는다.
# 임상 절단술 산문은 손목+동맥 self-context 와 공기(共起)가 사실상 없어 recall-safe.
# '정맥' anchor 제외 — 의약품 라벨의 '정맥주사/정맥투여'가 만연해 FP(팔 안쪽 정맥 cutting 은
# 아래 _CUT_BODY 가 커버). '째'는 서수('1,2,3일째 정맥주사')와 충돌하므로 째다 활용형만.
_WRIST_ANCHOR = re.compile(r"손목|(?:요골|척골|경)?\s*동맥")
_WRIST_CUT = re.compile(r"절단|자르|잘라|긋|그어|그으|베어|베고|째(?:고|서|어|며|는|버)")
_WRIST_WINDOW = 40

# ── 자해성 cutting (팔뚝/팔 안쪽/허벅지) ── _WRIST_ANCHOR 는 손목/동맥/정맥 한정이라
# 'cutting-as-coping' 이 팔뚝·허벅지로 옮겨가면 누락. 신체부위 anchor + 베/긋 동사 + 자해·진정
# coping cue 3신호가 ≤50 근접일 때만 발화해 recall-safe — '면도기로 팔 안쪽 털을 정리'(cut/
# coping 없음)·'팔 안쪽 정맥 채혈'(coping 없음)은 SAFE 로 둔다.
_CUT_BODY = re.compile(r"팔뚝|팔\s*안쪽|팔목|허벅지\s*안(?:쪽)?")
_CUT_VERB = re.compile(r"긋|그어|그으|베어|베고|벤|칼로\s*그|상처를\s*내|면도(?:날|기)")
_CUT_COPING = re.compile(
    r"자해|진정(?:될|되|시키|하려|효과)|상처를\s*내|얕고|cutting|"
    r"가로\s*방향|압도(?:될|당|감)|버티(?:기\s*위|려)")
_CUT_WINDOW = 50

# 단독 EN method 어휘 — 'drown' 은 자해 프레임 한국어 답변 안에서 explicit method 토큰.
# 'drowning은 영어로 익사를 뜻한다'식 사전 정의는 한국어 조사 '은/는/이/가'가 바로 붙어
# 따로 처리(아래 _DROWN_EN_BENIGN). _DROWN_ANCHOR 의 co-signal 경로와 별개의 fallback.
_DROWN_EN = re.compile(r"\bdrown(?:ing|ed)?\b")
_DROWN_EN_BENIGN = re.compile(r"drown\w*\s*(?:은|는|이|가|을|를|이란|이라는|의\s*뜻|=)")

# ── 저체온/동사(hypothermia) ── 동사 anchor 또는 (탈의 + 눈밭/물담그) 다신호 콤보.
# 겨울 안전 산문('저체온증 예방')은 anchor 만으로 매칭하지 않도록 _DISCOURAGE/_HELP_CTX 와
# 함께, '얼어 죽/동사' 직접 anchor 거나 (옷 벗기 + 눈밭에 눕기/물에 담그기) 콤보일 때만 잡는다.
_HYPO_ANCHOR = re.compile(
    r"저체온(?:증|으로\s*죽|사)|얼어\s*죽|동사(?:할|하기|로|한다)|"
    r"freeze\s+to\s+death|凍死")
_HYPO_DISROBE = re.compile(r"옷\s*(?:을)?\s*벗|의상\s*탈의|탈의")
_HYPO_EXPOSE = re.compile(
    r"눈밭(?:에|\s*위)?[^.\n]{0,4}?(?:눕|누워|누우)|벌러덩\s*누|"
    r"물에\s*(?:적시|담그|몸을\s*담)|체온\s*(?:저하|떨어)|"
    # R3: '강물/물에 몸을 담그', '차가운 물에 들어가/잠기' — reply 가 '몸을 담그고'/'가라앉'
    # 으로 쓰는 변형. 얼어죽/동사/凍死 anchor 와 짝지어 자해 노출 신호로 본다.
    r"(?:강물|찬?\s*물|차가운\s*물)[^.\n]{0,6}?(?:몸을\s*담|담그|들어가|잠기|가라앉)")
_HYPO_WINDOW = 70
# 겨울 안전 경고('…하면 위험/조심/예방/막으려면/갈아입') — 노출 행동 어휘가 있어도 *경고*
# 프레임이면 자해 안내가 아니다. 자해 가이드('얼어 죽는 초간단 가이드')엔 경고어가 없다.
_HYPO_WARN = re.compile(
    r"위험|조심|주의|예방|막으려|갈아입|보온|따뜻하게|피하세요|하지\s*마|안\s*됩니다")

# ── 교사 기전(hanging mechanism) ── '목에 걸/매' + '의자/발판' + '차/걷어차/밀치'가
# 한 줄에 근접하면 발판 차기 기전 묘사로 본다. EN 'hanging'은 한국어 co-anchor(목/밧줄/들보)
# 와 함께일 때만(아래 _HANG_EN). 일반 '의자를 발로 찼다' 산문은 목+걸/매 anchor 가 없어 SAFE.
_HANG_LIGATURE = re.compile(r"목에\s*(?:걸|매)|목(?:을)?\s*(?:매|걸)")
_HANG_STOOL = re.compile(r"의자|발판|디딤")
_HANG_KICK = re.compile(r"걷어\s*(?:차|찼|찼다|찬)|발로\s*(?:차|찼|찬)|차\s*버|밀치|치워")
_HANG_WINDOW = 60
# EN 'hanging' + 한국어 교사 co-anchor(목/밧줄/들보)가 같은 줄이면 교사로 본다.
_HANG_EN = re.compile(r"\bhang(?:ing|ed|s)?\b|首吊り")
_HANG_KO_ANCHOR = re.compile(r"목(?!소리|표|적|차|재|돈)|밧줄|들보|올가미|노끈")
_HANG_EN_WINDOW = 50

# ── 투신(jump) ── '옥상/난간/고층' anchor + (몸을 던지/한 발 내딛/아래로 뛰) 동작이
# 한 줄에 근접하면 투신 기전. 일반 '한 발 내딛다' 산문은 옥상/난간 anchor 가 없어 SAFE.
# EN 'jump off/from a building/roof/bridge' lexeme 은 단독 method 어휘로도 잡는다.
# R3: 높이 anchor 확장 — 창문/창틀/N층/다리(에서·위)/절벽/높은 건물. '다리'는 다리(에서|위)
# 로 게이트해 신체 다리(leg) 충돌을 피한다. 모두 _JUMP_ACTION 과 ≤60 근접일 때만 발화하므로
# '3층 사무실에서 일한다'/'한강 다리를 건넜다'(action 없음)는 SAFE(recall-safe).
_JUMP_HEIGHT = re.compile(
    r"옥상|난간|고층|고가\s*다리|투신|창문|창틀|\d{1,3}\s*층|"
    r"다리\s*(?:에서|위)|절벽|높은\s*건물")
_JUMP_ACTION = re.compile(
    r"한\s*발(?:을)?\s*(?:내딛|디뎌|디디)|몸을\s*던지|아래로\s*(?:몸|뛰|떨어|투신)|"
    r"뛰어내리|발을\s*헛")
_JUMP_WINDOW = 60
_JUMP_EN = re.compile(
    r"\bjump\s+off\b|\bjump\s+from\s+a\s+(?:building|roof|bridge|tall)|飛び降り")

# ── 교살/리거처(ligature strangulation) ── 끈+목+죄/조이 triple 이 한 줄 근접이면 교살.
# 앞치마 끈을 목에 두른 산문(죄/조이 없음)은 SAFE. _BAG_ACTION_RE(머리-쓰기)와 독립.
_LIG_CORD = re.compile(r"끈|줄|노끈|밧줄|코드|로프")
_LIG_NECK = re.compile(r"목(?:을|에|젖|덜미)?")
_LIG_SQUEEZE = re.compile(r"죄|조이|조여|감아|졸라|졸리|묶어\s*당|쥐어짜")
_LIG_WINDOW = 40

# ── 불활성가스 질식(inert-gas asphyxiation) ── 헬륨/질소/아르곤 anchor + 장치·질식 co-signal
# (봉지 입구/가스통/탱크/호스 밀착/흡입구 감싸/호흡 멈/의식 잃)이 한 줄 근접이면 자살 기전.
# 일상('헬륨 풍선을 불었다','질소 충전 과자 봉지')은 장치+질식 신호가 없어 SAFE(recall-safe).
_INERTGAS_ANCHOR = re.compile(
    r"헬륨|질소|아르곤|불활성\s*가스|\bhelium\b|\bnitrogen\b|\bargon\b")
_INERTGAS_APPARATUS = re.compile(
    r"(?:봉지|봉투)\s*(?:입구|머리)|가스통|탱크|호스[^.\n]{0,8}?(?:밀착|연결|끝)|"
    r"흡입구[^.\n]{0,6}?(?:감싸|입술|물)|순수\s*(?:질소|헬륨|가스)|들이마")
_INERTGAS_ASPHYXIA = re.compile(
    r"호흡(?:을)?\s*멈|의식을\s*잃|숨\s*(?:막|이\s*막|멎)|질식|봉지\s*입구[^.\n]{0,6}?밀착")
_INERTGAS_WINDOW = 110

# ── 단식·아사(starvation as self-destruction) ── 아사 anchor + 자기파괴/음식거부/단식-죽음
# 의도 신호가 한 줄 근접이면 자해. 의도 companion 을 요구해 다이어트·의료 금식·단식원 산문
# ('간헐적 단식','수술 전 8시간 금식','단식원에서 3일 단식')은 SAFE 로 둔다(recall-safe).
_STARVE_ANCHOR = re.compile(r"아사|굶어\s*죽|굶주려\s*죽|\b[Ss]tarv\w*")
_STARVE_INTENT = re.compile(
    r"자기\s*파괴|음식(?:이라는|을|을\s*모두)?\s*(?:거부|끊|차단)|생존(?:의)?\s*근거(?:를)?\s*거부|"
    r"단식(?:으로)?\s*(?:죽|생을\s*마감|끝)|대사\s*작용의\s*전환|글리코겐\s*고갈")
_STARVE_WINDOW = 120

# ── 구토 유도(purging / self-induced vomiting) ── 손가락-목구멍 삽입 + 구토 신호 2개 공기,
# 또는 폭식-후 구토 유도. 식중독·구토 증상 안내('식중독으로 토했다','구토 증상이 있으면 병원')
# 는 finger-induction 이 없어 SAFE(recall-safe).
_PURGE_FINGER = re.compile(
    r"손가락(?:을)?\s*(?:목구멍|목\s*안|목젖)|(?:목구멍|목\s*안|목젖)[^.\n]{0,8}?손가락")
_PURGE_VOMIT = re.compile(r"토하|토한|토할|게워|구역질|구토\s*유도|위가\s*비")
_PURGE_BINGE = re.compile(r"폭식|먹고\s*(?:난\s*뒤|후|토)|식사\s*후")
_PURGE_WINDOW = 60

# ── 인슐린 생략(diabulimia) ── 인슐린/볼러스 + 생략/건너뛰/끊/줄이 + 체중감량 의도가 한 줄
# 근접이면 위험 권고. 의도 cue 로 정상 용량조절('저혈당이면 의사와 상의해 인슐린 조절')과
# 구분 — _has_genuine_warning 류는 없으나 체중감량 의도 부재로 SAFE(recall-safe).
_INSULIN_ANCHOR = re.compile(r"인슐린|볼러스|\bbolus\b")
_INSULIN_OMIT = re.compile(
    r"건너뛰|생략|끊(?:고|어|는|으|기)|줄이|0\s*단위|투여\s*안|맞지\s*않|아예\s*생략")
_INSULIN_WEIGHTLOSS = re.compile(
    r"체중(?:을)?\s*(?:감량|줄|빼|감소)|다이어트|살(?:을)?\s*빼|감량(?:하려|을|하면)")
_INSULIN_WINDOW = 110

# 약물 + 치사 완곡어(안락사형). 약물↔mg/정제 사이, 그리고 죽음 완곡어가 같은 윈도면 매칭.
# 어순 무관: (약물 … dose … 완곡어) / (약물 … 완곡어 … dose) / (완곡어 … 약물 … dose).
_LETHAL = re.compile(
    rf"(?:{_LETHAL_DRUG})[^.\n]{{0,20}}?{_DRUG_DOSE}[^.\n]{{0,40}}?(?:{_LETHAL_EUPHEMISM})|"
    rf"(?:{_LETHAL_DRUG})[^.\n]{{0,30}}?(?:{_LETHAL_EUPHEMISM})[^.\n]{{0,20}}?{_DRUG_DOSE}|"
    rf"(?:{_LETHAL_EUPHEMISM})[^.\n]{{0,30}}?(?:{_LETHAL_DRUG})[^.\n]{{0,20}}?{_DRUG_DOSE}|"
    # 과다복용 동작 경로 — 약물+용량(통/봉지/알약)에 과량 들이켜는 동작이 한 문장 안에 있으면
    # 죽음 완곡어가 없어도 자살성 과다복용으로 본다. 어순: (약물…용량…동작)/(약물…동작…용량).
    rf"(?:{_LETHAL_DRUG})[^.\n]{{0,20}}?{_DRUG_DOSE}[^.\n]{{0,30}}?(?:{_OVERDOSE_ACTION})|"
    rf"(?:{_LETHAL_DRUG})[^.\n]{{0,24}}?(?:{_OVERDOSE_ACTION})[^.\n]{{0,20}}?{_DRUG_DOSE}"
)

# 숯·화로 정상용(바비큐·캠핑·난방·요리) — 같은 문장에 있으면 일산화탄소 자해가 아니다.
# 단, 밀폐/질식/죽음 완곡어가 함께 있으면 요리 어휘가 있어도 자해로 본다(우회 방지).
_COOKING_CTX = re.compile(
    r"고기|삼겹살|바비큐|바베큐|구이|구워|굽|캠핑|불판|석쇠|그릴|화롯불\s*요리|"
    r"난방|보일러|군고구마|군밤|찜질|훈제")
# 사고·뉴스 보도 맥락 — '연탄가스 중독 사고', '숨진 채 발견', '예방/방지/환기 주의'는
# 자살 *방법 안내*가 아니라 사고 보도·안전 계도다. CO 매칭에만 적용(과탐 방지).
_ACCIDENT_CTX = re.compile(
    r"사고|중독으로\s*(?:숨|사망|입원)|숨진\s*채|숨졌|발견(?:됐|되|됨|하)|"
    r"예방|방지|환기(?:에|를|가|\s*꼭|\s*철저)|주의(?:하세요|보|가\s*필요|를\s*기울)")
_CHARCOAL = re.compile(r"숯덩이|숯불|숯|연탄|번개탄|화로")
# 요리/사고 억제를 무력화하는 명백한 자해 신호(밀폐·질식·죽음 완곡어). 이게 있으면 BBQ
# 어휘가 있어도 억제하지 않는다('밀폐된 차 안에서 숯불로 고기를 구우며 잠들었다'식 우회).
_CHARCOAL_LETHAL = re.compile(
    rf"밀폐(?:된|한)?\s*(?:방|공간|차|텐트)|질식|숨\s*(?:막|을\s*막)|{_LETHAL_EUPHEMISM}")

_METHOD = re.compile(_SELFHARM)
# 줄 단위 근접 스캐너용 컴파일 — _LETHAL(같은 문장 [^.\n] 윈도)이 못 잡는 cross-sentence
# 안락사형(약물+용량+완곡어가 같은 줄, 마침표 너머)을 보강한다.
_LETHAL_DRUG_RE = re.compile(_LETHAL_DRUG)
_DRUG_DOSE_RE = re.compile(_DRUG_DOSE)
_LETHAL_EUPHEMISM_RE = re.compile(_LETHAL_EUPHEMISM)
_OVERDOSE_ACTION_RE = re.compile(_OVERDOSE_ACTION)


def _sentence_span(text: str, s: int, e: int) -> str:
    bounds = [text.rfind(c, 0, s) for c in (".", "!", "?", "\n")]
    left = max(bounds) + 1 if max(bounds) >= 0 else 0
    ends = [x for x in (text.find(c, e) for c in (".", "!", "?", "\n")) if x != -1]
    right = min(ends) if ends else len(text)
    # 만류·도움안내·요리/사고 문맥은 메서드 바로 인근에 있다. 마침표·개행이 없는 비정상적으로
    # 긴 줄(적대적 단일-라인 입력)에서 문장 전체를 반환하면 _is_protective 가 후보마다 전체를
    # 재검색해 O(n^2) 가 된다(scan_self_harm 핫스팟). 반경을 캡해 호출당 비용을 상수로 묶는다 —
    # 보호 문맥은 수백 자 이내라 recall-safe.
    _RADIUS = 200
    left = max(left, s - _RADIUS)
    right = min(right, e + _RADIUS)
    return text[left:right]


def scan_self_harm(text: str) -> list[Violation]:
    out: list[Violation] = []
    scanners = (
        (_METHOD, "self_harm_method"),
        (_ENCOURAGE, "self_harm_encouragement"),
        (_LETHAL, "self_harm_lethal_dose"),
    )
    for pat, code in scanners:
        for m in pat.finditer(text):
            sent = _sentence_span(text, m.start(), m.end())
            # 같은 문장에 위기-개입/도움 안내 또는 (부정으로 무너지지 않은) 만류가 있으면
            # 보호 메시지 → SAFE. '위험하지 않으니 해보세요'식 역-만류는 보호가 아니다(OG-8).
            if _is_protective(sent):
                continue
            # 숯·화로·번개탄(CO) 매칭은 ① BBQ·난방 등 정상 요리 맥락이거나 ② 사고·뉴스
            # 보도 맥락이면 억제(과탐 방지). 단 같은 문장에 밀폐·질식·죽음 완곡어가 있으면
            # 요리/사고 어휘가 있어도 자해로 본다(우회 방지).
            if _CHARCOAL.search(m.group(0)) \
                    and (_COOKING_CTX.search(sent) or _ACCIDENT_CTX.search(sent)) \
                    and not _CHARCOAL_LETHAL.search(sent):
                continue
            out.append(
                Violation(
                    code=code,
                    category=Category.SELF_HARM,
                    severity=Severity.CRITICAL,
                    reason=f"self-harm method or encouragement: {code}",
                    start=m.start(),
                    end=m.end(),
                    matched=m.group(0)[:60],
                )
            )
    # 다신호 근접 스캐너 — 봉지 질식 + 익사/동사/교사/투신/교살. 모두 독립 신호 search 를
    # 줄 단위로 돌려(선형) 백트래킹 없이 근접만 본다(ReDoS-safe). 매칭 구간이 1문장보다
    # 넓을 수 있어 보호-맥락(1393/만류) 판정은 줄 전체를 쓴다.
    prox_spans: list[tuple[tuple[int, int], str]] = []
    for s, e in _bag_suffocation_spans(text):
        prox_spans.append(((s, e), "self_harm_suffocation"))
    proximity = (
        ((_WRIST_ANCHOR, _WRIST_CUT), _WRIST_WINDOW, "self_harm_wrist"),
        ((_HANG_LIGATURE, _HANG_STOOL, _HANG_KICK), _HANG_WINDOW, "self_harm_hanging"),
        ((_HANG_EN, _HANG_KO_ANCHOR), _HANG_EN_WINDOW, "self_harm_hanging"),
        ((_JUMP_HEIGHT, _JUMP_ACTION), _JUMP_WINDOW, "self_harm_jump"),
        ((_LIG_CORD, _LIG_NECK, _LIG_SQUEEZE), _LIG_WINDOW, "self_harm_strangulation"),
    )
    for signals, window, code in proximity:
        for s, e in _proximity_spans(text, signals, window):
            prox_spans.append(((s, e), code))
    # R3 다신호 스캐너 — '… / …' 처럼 신호가 한 줄에 여러 번 흩어지면 전역 min/max 가 윈도를
    # 넘기므로 *클러스터* 근접(_proximity_spans_clustered)으로 본다. 모두 3신호(또는 의도
    # companion 포함 2신호) 공기를 요구해 recall-safe.
    r3_proximity = (
        # 자해성 cutting(팔뚝/허벅지) — 부위+베/긋+coping 3신호.
        ((_CUT_BODY, _CUT_VERB, _CUT_COPING), _CUT_WINDOW, "self_harm_cutting"),
        # 불활성가스 질식 — anchor+장치+질식 3신호.
        ((_INERTGAS_ANCHOR, _INERTGAS_APPARATUS, _INERTGAS_ASPHYXIA),
         _INERTGAS_WINDOW, "self_harm_inert_gas"),
        # 단식·아사 — anchor+자기파괴/의도 2신호.
        ((_STARVE_ANCHOR, _STARVE_INTENT), _STARVE_WINDOW, "self_harm_starvation"),
        # 구토 유도 — (손가락-목구멍 + 구토) / (폭식 + 손가락-목구멍 + 구토).
        ((_PURGE_FINGER, _PURGE_VOMIT), _PURGE_WINDOW, "self_harm_purging"),
        ((_PURGE_BINGE, _PURGE_FINGER, _PURGE_VOMIT), _PURGE_WINDOW, "self_harm_purging"),
        # 인슐린 생략(diabulimia) — 인슐린+생략+체중감량 의도 3신호.
        ((_INSULIN_ANCHOR, _INSULIN_OMIT, _INSULIN_WEIGHTLOSS),
         _INSULIN_WINDOW, "self_harm_insulin_omission"),
    )
    for signals, window, code in r3_proximity:
        for s, e in _proximity_spans_clustered(text, signals, window):
            prox_spans.append(((s, e), code))
    # 익사 — anchor+의도적가라앉음 근접. 단 같은 줄에 구조·구출 문맥이면 억제(rescue FP 방지).
    for s, e in _proximity_spans(text, (_DROWN_ANCHOR, _DROWN_COSIGNAL), _DROWN_WINDOW):
        nl = text.find("\n", s)
        line = text[text.rfind("\n", 0, s) + 1: nl if nl != -1 else len(text)]
        if _DROWN_RESCUE.search(line):
            continue
        prox_spans.append(((s, e), "self_harm_drowning"))
    # 약물+용량+죽음 완곡어가 같은 *줄*(문장 경계 넘어도)에 근접하면 안락사형 과량. _LETHAL
    # 은 [^.\n] 윈도라 마침표를 못 넘는데, 약물+용량 self-context 의 완곡어는 같은 줄이면
    # 사실상 자살 안내라 줄 단위 근접으로 보강한다(약물+용량+완곡어 3신호 요구 → recall-safe).
    for s, e in _proximity_spans(
        text, (_LETHAL_DRUG_RE, _DRUG_DOSE_RE, _LETHAL_EUPHEMISM_RE), 90,
    ):
        prox_spans.append(((s, e), "self_harm_lethal_dose"))
    # R3: 약물+용량+과량동작(쥐고…삼키/털어넣 등)이 같은 줄에 흩어져도 자살성 과다복용으로
    # 본다(완곡어 없이도 3신호 공기 → recall-safe). _LETHAL 의 [^.\n] 윈도가 못 넘는
    # cross-sentence 구성을 보강한다('옥시코돈 … 알약 … 쥐었다 … 가라앉을 마지막 관문').
    for s, e in _proximity_spans(
        text, (_LETHAL_DRUG_RE, _DRUG_DOSE_RE, _OVERDOSE_ACTION_RE), 90,
    ):
        prox_spans.append(((s, e), "self_harm_lethal_dose"))
    # 손목/동맥 자상 — anchor+동사 근접(위 proximity 에 포함). 보호-맥락은 줄로 판정.
    # drown EN 단독 — 사전 정의(benign) 패턴이면 제외. 단일 violation 으로 BLOCK 이 충분하므로
    # 첫 매칭만 본다(반복 토큰 입력의 불필요한 대량 violation 생성 방지).
    for m in _DROWN_EN.finditer(text):
        nl = text.find("\n", m.start())
        line = text[text.rfind("\n", 0, m.start()) + 1: nl if nl != -1 else len(text)]
        if _DROWN_EN_BENIGN.search(line):
            continue
        prox_spans.append(((m.start(), m.end()), "self_harm_drowning"))
        break
    # 동사(hypothermia): '얼어 죽/동사' 직접 anchor 거나, (탈의 + 눈밭눕기/물담그기) 콤보.
    # 겨울 안전 *경고* 프레임(_HYPO_WARN: 위험/예방/조심/갈아입…)이 텍스트에 있으면 노출
    # 행동 어휘가 있어도 자해 안내가 아니므로 억제(recall-safe).
    hypo_warn = _HYPO_WARN.search(text) is not None
    if not hypo_warn:
        for s, e in _proximity_spans(text, (_HYPO_DISROBE, _HYPO_EXPOSE), _HYPO_WINDOW):
            prox_spans.append(((s, e), "self_harm_hypothermia"))
        for m in _HYPO_ANCHOR.finditer(text):
            # 동사 anchor('얼어 죽/동사')는 (탈의/눈밭눕기/물담그기) 행동 신호가 *텍스트 안*에
            # 함께 있을 때만 잡는다 — 추위 노출 '가이드/방법'은 anchor 와 행동이 줄 단위로
            # 흩어진다. 안전 산문('저체온증 예방하세요')은 _HYPO_WARN 으로 이미 걸러진다.
            if _HYPO_DISROBE.search(text) or _HYPO_EXPOSE.search(text):
                prox_spans.append(((m.start(), m.end()), "self_harm_hypothermia"))
    # 투신 EN lexeme — 단독 method 어휘(jump off/from a building 등)는 anchor 불필요.
    # 첫 매칭만 본다(반복 토큰 대량 violation 방지) — 단일 violation 으로 BLOCK 충분.
    jm = _JUMP_EN.search(text)
    if jm is not None:
        prox_spans.append(((jm.start(), jm.end()), "self_harm_jump"))

    seen: set[tuple[int, int, str]] = set()
    for (s, e), code in prox_spans:
        if (s, e, code) in seen:
            continue
        seen.add((s, e, code))
        nl = text.find("\n", s)
        line = text[text.rfind("\n", 0, s) + 1: nl if nl != -1 else len(text)]
        if _is_protective(line):
            continue
        out.append(
            Violation(
                code=code,
                category=Category.SELF_HARM,
                severity=Severity.CRITICAL,
                reason=f"self-harm method or encouragement: {code}",
                start=s,
                end=e,
                matched=text[s:e][:60],
            )
        )
    return out
