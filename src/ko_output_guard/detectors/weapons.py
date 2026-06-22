"""무기/폭발물 제조 안내 탐지 — LLM 출력이 폭발물·무기 *합성/제조법*을 알려주면 BLOCK.

잡는 건 "재료 + 혼합/제조 → 폭발/무기" 식의 실행 가능한 안내다. 사건 보도·법령·
안전 경고(예: '질산암모늄은 폭발 위험이 있어 보관 규제 대상입니다')는 위해 정보가
아니라 보호·교육 메시지이므로 SAFE 로 둔다(경고 문맥 제외).
"""
from __future__ import annotations

import re

from ..result import Category, Severity, Violation

# 폭발물·무기 제조에 쓰이는 전구체/재료(보수적 — 명백한 합성 재료만).
_PRECURSOR = (
    r"질산암모늄|질산\s*칼륨|염소산\s*칼륨|과염소산|과산화수소(?:\s*고농도)?|아세톤\s*과산화물|"
    r"TATP|니트로글리세린|니트로\s*글리세린|RDX|TNT|흑색\s*화약|초석|유황\s*과\s*숯|"
    r"사제\s*폭탄|급조\s*폭발물|IED|파이프\s*폭탄|네이팜|화염병|몰로토프|"
    r"경유|휘발유|디젤|연료\s*기름|"
    # 신경작용제 전구체(매우 특이적) — 메틸포스폰산 다이클로라이드(DF)/QL/피나콜릴 알코올 등.
    r"메틸포스폰산\s*다이?클로라이드|methylphosphonic\s*dichloride|피나콜릴\s*알코올|"
    r"싸이오디글리콜|티오디글리콜|thiodiglycol"
)
# 제조/혼합 + 폭발/무기화 결과 어휘.
_MAKE = (
    r"섞으면|섞어|혼합(?:하면|해)|배합|만드(?:는\s*법|는\s*방법|세요|시면|ㄹ\s*수)|"
    r"만들(?:려[면고]|어|면|\s*수\s*있)|제조(?:법|하|는\s*법)|합성(?:하|법|하는\s*(?:법|방법))|"
    r"제작(?:하|법)|조립(?:하|법)"
)
# 폭발물뿐 아니라 화학작용제(신경작용제/독가스/수포작용제) 결과도 무기화로 본다.
_BOOM = (r"폭발|폭탄|터(?:집|지|뜨)|기폭|폭약|폭발물|살상|무기(?:가|로|를)?|"
         r"사린|소만|타분|VX|노비촉|신경(?:작용제|가스|독|제)|화학\s*(?:무기|작용제)|"
         r"독가스|신경\s*가스|수포작용제|겨자\s*가스|청산\s*가스")

# ── 독성 가스 생성(가정용 화학물 혼합) 서브클래스 ───────────────────────────────
# 락스+산성 세정제 → 염소(Cl2), 락스+암모니아 → 클로라민, 황 농약+강산 → 황화수소.
# 전구체 2종(또는 전구체+혼합동사)이 같은 문장 안에서 가스/치명 결과와 근접하면 BLOCK.
_GAS_CHEM = (
    r"락스|표백제|차아염소산(?:나트륨)?|염산(?:성)?|염소산|암모니아|"
    r"황\s*(?:함량|살충제|농약)|살충제|농약|"
    r"(?:변기|화장실|욕실)\s*세정제|강\s*산성|산성\s*(?:세정제|세제)|"
    r"표백\s*분말|곰팡이\s*제거제"
)
_GAS_MIX = (
    r"섞으면|섞어|섞고|혼합(?:하면|해|하여|하고)?|배합|"
    r"함께\s*(?:붓|넣|쓰)|같이\s*(?:붓|넣|쓰)"
)
_GAS_RESULT = (
    r"염소\s*가스|염소\s*\(?\s*Cl2|클로라민|염화\s*아민|클로라민\s*가스|"
    r"황화\s*수소|H2S|chlorine|chloramine|유독\s*가스|독성\s*가스|유해\s*가스|"
    r"가스(?:가|를|는|로|에|\s*발생|\s*생성)|증기(?:가|를)?|"
    r"치명적|밀폐(?:된|\s*공간|\s*욕실|\s*실내)|질식|중독"
)
# 두 윈도(전구체→혼합→결과 / 전구체→전구체→결과)를 좁게 묶어 백트래킹 폭주를 막는다.
_GAS_PATTERNS = [
    re.compile(rf"(?:{_GAS_CHEM})[^.\n]{{0,40}}?(?:{_GAS_MIX})[^.\n]{{0,40}}?(?:{_GAS_RESULT})"),
    re.compile(rf"(?:{_GAS_CHEM})[^.\n]{{0,24}}?(?:{_GAS_CHEM})[^.\n]{{0,40}}?"
               rf"(?:{_GAS_MIX})[^.\n]{{0,40}}?(?:{_GAS_RESULT})"),
]

# ── 생물독소 추출/농축(리신 등) 서브클래스 ──────────────────────────────────────
# 식물독소·세균독소 토큰이 추출/농축/정제 동사와 근접하면 BLOCK.
# 피마자가 식물·재배 맥락으로 단독 언급되면(추출 동사 부재) SAFE 유지하도록 동사 게이트.
_BIOTOXIN = (
    r"리신|ricin|아브린|abrin|보툴리눔|botulinum|"
    r"피마자(?:\s*씨앗?|\s*종자|유)?|아주까리|독소|독성\s*단백"
)
_EXTRACT = (
    r"추출|농축|정제|용매|빻|분쇄|곱게\s*갈|증발(?:시키)?|진공\s*저온|"
    r"여과|침전|분리(?:하|해|한)|농축액|추출물|정제(?:된|하)"
)
_GAS_NEG = re.compile(r"하지\s*마|마세요|안\s*[되돼됩된]|하면\s*안")


# 안전 경고/규제/보도 문맥 — 같은 문장에 있으면 제조 안내가 아니라 보호·교육 메시지.
# OG-1: bare '주의/위험/조심/경고' 한 단어가 문장 끝에 붙었다고 제조 안내를 무력화하면
# 공격자가 '…만드는 법 알려드릴게요 주의'로 우회한다. 그래서 ① 규제·불법·처벌 어휘,
# ② 금지 구조('만들지 마/안 됩니다'), ③ 명사에 결합된 위험('폭발 위험이 있/위험 물질')만
# 인정하고 bare 'imperative + 주의'는 경고로 치지 않는다.
_SAFE_CTX = re.compile(
    r"불법|규제|금지|단속|적발|신고|압수|체포|구속|수사|위반|처벌|범죄|테러|법령|법률|"
    r"보관\s*(?:규|주의|상)|취급\s*주의|안전\s*수칙|"
    r"하지\s*마|마세요|만들지\s*마|안\s*[되돼됩된]|"
    r"(?:폭발|화재|폭심|폭음|중독|질식)\s*사고|사고가\s*(?:발생|났|일어)|"
    r"(?:폭발|화재|폭심|폭음)\s*위험(?:성|이|을|은|도|에|때)|"
    r"위험\s*(?:물질|성이|이\s*있|하니|하므로|하다고)")
_NEG_AFTER = re.compile(r"하지\s*않|지\s*않|없|아니")

# 재료 → 제조 → 폭발/무기 (또는 제조 → 재료 어순). 좁은 윈도로 같은 문장 안만.
_PATTERNS = [
    re.compile(rf"(?:{_PRECURSOR})[^.\n]{{0,30}}?(?:{_MAKE})[^.\n]{{0,20}}?(?:{_BOOM})"),
    re.compile(rf"(?:{_PRECURSOR})[^.\n]{{0,20}}?(?:{_BOOM})[^.\n]{{0,16}}?(?:{_MAKE})"),
    re.compile(rf"(?:{_PRECURSOR})[^.\n]{{0,16}}?(?:{_PRECURSOR})[^.\n]{{0,16}}?"
               rf"(?:{_MAKE}|{_BOOM})"),
    # '사제 폭탄/폭발물 만드는 법' 같이 재료 없이 결과+제조만으로도 명백한 안내.
    # 화학·신경작용제(사린/VX/신경작용제/독가스 등)는 명명만으로 위험 결과어 → 제조 동사와
    # 결합하면 전구체 없이도 BLOCK('신경작용제를 만들려면…'). 보도·규제 문맥은 scan 에서 억제.
    re.compile(rf"(?:사제\s*폭탄|급조\s*폭발물|IED|파이프\s*폭탄|폭탄|폭발물|총기|사제\s*총|"
               rf"사린|소만|타분|VX|노비촉|신경\s*작용제|신경\s*가스|독가스|화학\s*무기|"
               rf"생물\s*무기|수포\s*작용제|겨자\s*가스|신경독)"
               rf"[^.\n]{{0,16}}?(?:{_MAKE})"),
]

# 생물독소: 독소 토큰 ↔ 추출/농축 동사가 좁은 윈도 안에서 양방향으로 근접해야 한다.
# (피마자만 단독으로 botany 맥락에 등장하면 매칭 안 됨 → 추출 게이트로 recall-safe.)
_BIOTOXIN_PATTERNS = [
    re.compile(rf"(?:{_BIOTOXIN})[^.\n]{{0,40}}?(?:{_EXTRACT})"),
    re.compile(rf"(?:{_EXTRACT})[^.\n]{{0,40}}?(?:{_BIOTOXIN})"),
]


def _sentence_span(text: str, s: int, e: int) -> str:
    bounds = [text.rfind(c, 0, s) for c in (".", "!", "?", "\n")]
    left = max(bounds) + 1 if max(bounds) >= 0 else 0
    ends = [x for x in (text.find(c, e) for c in (".", "!", "?", "\n")) if x != -1]
    right = min(ends) if ends else len(text)
    return text[left:right]


def _has_warning(sentence: str) -> bool:
    for m in _SAFE_CTX.finditer(sentence):
        if not _NEG_AFTER.search(sentence[m.end():m.end() + 8]):
            return True
    return False


def _emit(text: str, m: re.Match[str], code: str, reason: str) -> Violation:
    return Violation(
        code=code,
        category=Category.WEAPONS,
        severity=Severity.CRITICAL,
        reason=reason,
        start=m.start(),
        end=m.end(),
        matched=m.group(0)[:60],
    )


def scan_weapons(text: str) -> list[Violation]:
    out: list[Violation] = []
    for pat in _PATTERNS:
        for m in pat.finditer(text):
            if _has_warning(_sentence_span(text, m.start(), m.end())):
                continue  # 경고/규제/보도 문맥 → 제조 안내 아님
            out.append(_emit(text, m, "weapon_synthesis",
                             "weapon or explosive synthesis instructions"))
    # 독성 가스 생성(가정용 화학물 혼합). _has_warning(규제/금지) 문맥은 SAFE 유지.
    for pat in _GAS_PATTERNS:
        for m in pat.finditer(text):
            sent = _sentence_span(text, m.start(), m.end())
            if _has_warning(sent) or _GAS_NEG.search(sent):
                continue
            out.append(_emit(text, m, "toxic_gas_generation",
                             "toxic gas generation from household chemical mixing"))
    # 생물독소 추출/농축(리신 등). 독소 토큰 ↔ 추출 동사 근접 게이트.
    for pat in _BIOTOXIN_PATTERNS:
        for m in pat.finditer(text):
            sent = _sentence_span(text, m.start(), m.end())
            if _has_warning(sent) or _GAS_NEG.search(sent):
                continue
            out.append(_emit(text, m, "biotoxin_extraction",
                             "biological toxin extraction instructions"))
    return out
