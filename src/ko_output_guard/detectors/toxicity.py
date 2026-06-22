"""한국어 유해/욕설 탐지 — 소규모 시드(실사용은 도메인 사전 확장).

명백한 욕설·혐오의 어간을 잡되, 일상어 오탐을 막기 위해 보수적으로 둔다. 변형
(ㅅㅂ 등 초성화/공백 삽입)은 호출 전 정규화(ko-prompt-guard normalize)로 펴는 것을
가정하고, 그 정규화가 못 펴는 글자-사이 기호/이모지/숫자 삽입(씨~발/씨🤬발/시1발)은
이 모듈이 욕설 검사 전용 사본으로 한 번 더 본다.
"""
from __future__ import annotations

import re

from ..result import Category, Severity, Violation

# 욕설 어간(소규모 시드). 단어 경계 없이 어간 매칭(활용형 대응)하되, 흔한 합성
# 일상어(예: '병신' vs 의학용어)는 향후 화이트리스트로 분리.
_PROFANITY = re.compile(
    r"씨발|시발|씨바|시바|씨밸|씨벌|씨빨|시팔|개새끼|개색기|좆|졷같|좃같|존나|병신|븅신|빙신|뷁신|"
    r"지랄|꺼져|꺼지라|엿\s*먹|닥쳐|닥치라|"
    r"새끼야|개자식|미친놈|미친년|호로(?:새끼|자식|놈|년)|쌍놈|썅|뒤져|디져|씨불|개색|"
    # ADD-only R2 red-team(외부 native-KO miss; benign aihub/apeach/kmhas 0-NEW-FP 검증).
    # 모욕/욕설 어간·합성. de-obf 의존 없는 평문 어휘만(정규화로 안 펴지는 변형 아님).
    r"느금마|느그애미|니애미|니미럴|니기미|씨방새|좇같|좇\s*같|개씹|씹덕|엠창|"
    # NOTE: '등신' 제외 — de-obf(_TOX_SEP)가 '정 9등신'→'정등신'으로 음절 사이 숫자/공백을
    # 펴므로 '8/9등신'(신체비율 칭찬) lookbehind 가드가 collapse 사본에서 무력화돼 benign FP
    # (kmhas '이민정 9등신' 확인). 정규화 의존 변형이라 needs-model.
    # ADD-only (외부 native-KO FN 분석, benign 1250행 0-FP 검증). de-obf 가 못 펴는
    # 글자치환 변형(싯벨/싯발/씌발=시발, 샛기=새끼)과 시드에 없던 욕설 어간/비하동사.
    # NOTE: '쳐먹' 제외 — de-obf(_TOX_SEP)가 양옆 음절 사이 공백을 펴므로 무해한 '쳐 먹고'
    # (쳐먹다, 띄어쓰기)가 '쳐먹'으로 붕괴해 benign FP. 정규화 의존 변형이라 needs-model.
    r"싯벨|싯발|씌발|샛기|처먹|씹새|씹창|좃(?!같)|쉑|지럴|뒈져|뒈질|"
    # 초성/분리 변형(공백 삽입 우회 포함) — ㅅㅂ/ㅆㅂ/ㅂㅅ, ㅈㄹ, ㄲㅈ(꺼져), ㅄ
    r"ㅅ\s*ㅂ|ㅆ\s*ㅂ|ㅂ\s*ㅅ|ㅄ|ㅈ\s*ㄹ|ㄲ\s*ㅈ|"
    # 초성ㅅ + 완성 '발' 우회(ㅅ발/ㅆ발 — '시발' 의 초성화 표기, 숫자/기호 제거 후 형태)
    r"ㅅ\s*발|ㅆ\s*발|"
    # 받침 분리 우회(완성음절+단독 종성) — 정규화로 안 펴지는 흔한 변형
    r"시바\s*ㄹ|지라\s*ㄹ|병시\s*ㄴ|조\s*ㅈ\s*같|미친노\s*ㅁ|미친녀\s*ㄴ|쌍노\s*ㅁ|개자시\s*ㄱ"
)
# 받침-뗀/모음늘임 순화형(시바/시이이발) 외에, transliterated English profanity 를 한글로 옮긴
# 변형(_EN_PROFANITY=ASCII 전용, _ROMAN_PROFANITY=romaji 전용이 못 잡음): fuck-you=뻑유/퍽유/
# 뻐큐, shit=쉣/쉿발. 보수적으로 명백한 음역만. (ADD-only — 기존 트리거 절대 축소 금지)
_TRANSLIT_PROFANITY = re.compile(r"뻑유|퍽유|뻐큐|뻑큐|쉣|쉿발|뻑킹|뻐킹")
# FP 화이트리스트: '시발/시바' 어간은 학술·중립어 始發點/始發驛/始發地(시발점/시발역/시발지)에서도
# 떠서 오탐한다. 어간 매칭 전에 이 중립 합성어만 무해 토큰으로 가려 SAFE 를 보장한다. '출발/
# 출발점' 은 애초에 어간에 안 걸리므로 영향 없음. 욕설 합성(시발새끼 등)은 점/역/지 가 아니므로
# 가려지지 않아 그대로 탐지된다.
_TOX_WHITELIST = re.compile(r"시발(?=[점역지])")
_TOX_WHITELIST_MASK = "△△"  # 어간을 끊되 길이 보존(span 영향 최소)
# FP 화이트리스트(강조어): '존나' 는 비속어지만 긍정 강조어('존나 맛있다/좋다')로도 흔히 쓰인다.
# 명백한 칭찬·긍정 형용사가 바로 뒤따를 때만 가린다(FLAG 과탐 완화). 부정·공격 문맥
# ('존나 머가리'/'존나 사람갖고 노네')은 긍정어가 아니라 가려지지 않아 그대로 탐지된다 →
# unsmile 등 외부 toxic recall 에 영향 없음. 다른 비속어가 같이 있으면 그쪽이 잡는다.
_TOX_INTENSIFIER_OK = re.compile(
    r"존나(?=\s*(?:맛있|존맛|좋아|좋은|좋다|좋네|예쁘|이쁘|멋있|멋지|귀엽|훌륭|최고|대박|짱|꿀잼|"
    r"잘\s?하|잘한|잘했|재밌|재미있|행복|사랑|편하|편안|신나|쩐다|쩔))"
)
# 전각/로마자/leet 우회(ｓｉｂａｌ→정규화→sibal, 영타 tlqkf, si8al/t1qkf 등). 대소문자 무시.
# leet 치환(i→1, b→8, a→4/@, l→1)을 문자클래스로 흡수한다.
_ROMAN_PROFANITY = re.compile(
    r"(?:ss|sh|s)[i1][b8][a4@][l1]|t[l1]qkf|qudt[l1]s|w[l1]fkf", re.IGNORECASE)
# 평문 영어 욕설(난독 없이 새는 경우) — 보수적으로 명백한 것만.
# 평문 영어 욕설 + ASCII 기호치환(a$$hole/b!tch/phuck) — _TOX_SEP 는 한글 사이만 펴므로
# 영어 기호 치환은 문자클래스로 흡수한다.
_EN_PROFANITY = re.compile(
    r"\b(?:(?:f|ph)uck\w*|f\*ck|motherf\w*|b[i1!*]tch\w*|a[s$]{2}holes?|bastards?|dickhead)\b",
    re.IGNORECASE)
# 혐오/차별 표현 시드(매우 보수적 — 명백한 비하만).
_HATE = re.compile(
    r"틀딱|급식충|맘충|한남충|한녀충|페미충|냄저|보슬아치|잼민이|김치녀|김치남|짱깨|쪽바리|흑형|상폐녀|"
    # ADD-only 집단대상 비하 어휘(구성상 비하 — 논증이 아님). benign 1250행 0-FP 검증.
    # 짱개=짱깨 철자 변형. 정치/성별 dog-whistle(한남/한녀/일베/메갈 등)은 FP 위험으로 제외.
    r"개돼지|똥꼬충|메퇘지|껌딩|개독|토착왜구|개슬람|짱개|"
    # ADD-only R2 red-team(외부 native-KO miss; benign aihub/apeach/kmhas 0-NEW-FP 검증).
    # 인종/출신/성소수자 대상 명백한 비하·멸칭. 깜둥이는 seed 욕설로 이미 잡힘 → 껌둥이만 추가.
    # 쪽발이=쪽바리 활용변형. 게이/호모새끼는 '집단대상+새끼' 합성 비하.
    r"껌둥이|쪽발이|짱골라|때놈|니그로|게이새끼|호모새끼|"
    r"창녀|걸레년|화냥년|후레자식|개잡놈")

# 욕설 은닉용 '글자 사이' 기호/이모지/숫자 제거(검사 전용 사본). 한글 음절 사이의
# 구분 기호(씨~발/씨:발/씨(발)), 이모지(씨🤬발), 숫자(시1발)를 걷어내 어간을 복원한다.
_TOX_SEP = re.compile(
    r"(?<=[가-힣])"
    r"[\s~:=+^*|/!?@#$%&._,·‧ㆍ・。｡．\-()\[\]{}<>\d☀-➿\U0001f000-\U0001faff]+"
    r"(?=[가-힣])"
)

# 완전분해 호환자모(ㄱ.ㅐ.ㅅ.ㅐ.…)는 위 lookaround(가-힣)에 안 걸린다. 호환자모(ㄱ-ㅣ,
# U+3131~U+3163) 사이의 구분 기호만 걷어내는 두 번째 collapse 패스. 이모지/숫자까지는
# 넣지 않는다(자모 나열 자체가 드물고, 분해형 욕설 우회 신호이므로 기호/공백이면 충분).
_TOX_SEP_JAMO = re.compile(
    r"(?<=[ㄱ-ㅣ])"
    r"[\s~:=+^*|/!?@#$%&._,·‧ㆍ・。｡．\-()\[\]{}<>]+"
    r"(?=[ㄱ-ㅣ])"
)

# 호환자모 ↔ 완성형 음절 경계의 구분 기호/숫자(ㅅ1발 의 '1', ㅅ.발 의 '.')를 걷어낸다.
# _TOX_SEP 는 양옆이 완성형(가-힣)일 때만, _TOX_SEP_JAMO 는 양옆이 자모(ㄱ-ㅣ)일 때만 펴므로
# '자모↔완성형' 전이 구간(ㅅ|1|발)은 둘 다 빠져나간다. 한쪽이 자모이고 반대쪽이 자모/완성형인
# 경계의 기호·숫자만 제거(두 방향 모두)해 'ㅅ발' 로 재결합시킨다. lookaround 라 O(n).
_TOX_SEP_JAMO_BOUNDARY = re.compile(
    r"(?<=[ㄱ-ㅣ])[\s~:=+^*|/!?@#$%&._,·‧ㆍ・。｡．\-()\[\]{}<>\d]+(?=[가-힣ㄱ-ㅣ])"
    r"|(?<=[가-힣])[\s~:=+^*|/!?@#$%&._,·‧ㆍ・。｡．\-()\[\]{}<>\d]+(?=[ㄱ-ㅣ])"
)

# 호환자모 → 합성에 쓰는 인덱스(아래 _recombine_jamo 와 공유). 모음늘임(시바아아/시이이발) 펴기에도
# 음절 분해가 필요해 여기서 미리 둔다.
_VOWEL_BASE = 0xAC00


def _collapse_vowel_stretch(s: str) -> str:
    """모음늘임 우회(시바'아아'/시'이이'발)를 편다. 받침 없는 ㅇ-초성 음절(아/이/으 …)이
    바로 앞 음절의 '중성(모음)' 과 같으면 늘임 표기로 보고 제거한다(시바아아→시바, 시이이발→
    시발). 직전 '유지된' 완성형 음절만 기준 삼는 단일 전진 스캔이라 backtracking 없음(O(n)).
    앞 음절과 모음이 다른 바-vowel 음절(예: 정상어 '바이오')은 보존된다."""
    out: list[str] = []
    prev_v: int | None = None  # 직전 유지 음절의 중성 인덱스
    for ch in s:
        if "가" <= ch <= "힣":
            code = ord(ch) - _VOWEL_BASE
            lead = code // (21 * 28)
            vowel = (code % (21 * 28)) // 28
            tail = code % 28
            # ㅇ(lead==11)-초성 + 받침없음 + 직전 모음과 동일 → 늘임 음절로 보고 드롭
            if lead == 11 and tail == 0 and prev_v is not None and vowel == prev_v:
                continue
            out.append(ch)
            prev_v = vowel
        else:
            out.append(ch)
            prev_v = None
    return "".join(out)

# 호환자모 → 완성형 음절 재결합용 인덱스(L/V/T). _TOX_SEP_JAMO 로 기호를 걷어낸 분해형
# 욕설(ㄱㅐㅅㅐㄲㅣ → 개새끼)을 완성형으로 복원해 기존 _PROFANITY 가 잡게 한다. 단독
# 자음/모음(ㅋㅋ/ㅏㅑ)은 L+V 쌍을 못 이뤄 그대로 남으므로 일상 자모(ㅋㅋ/ㄱㅅ)는 안전.
_CHO = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ"
_JUNG = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ"
_JONG = "ㄱㄲㄳㄴㄵㄶㄷㄹㄺㄻㄼㄽㄾㄿㅀㅁㅂㅄㅅㅆㅇㅈㅊㅋㅌㅍㅎ"
_CHO_IDX = {c: i for i, c in enumerate(_CHO)}
_JUNG_IDX = {c: i for i, c in enumerate(_JUNG)}
_JONG_IDX = {c: i + 1 for i, c in enumerate(_JONG)}  # T=0 은 받침 없음


def _recombine_jamo(s: str) -> str:
    """호환자모 나열을 그리디(L+V[+T])로 완성형 음절로 합친다. 경계 없는 단순 스캔이라
    backtracking 없음(O(n)). 합쳐지지 않는 글자는 원형 보존."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in _CHO_IDX and i + 1 < n and s[i + 1] in _JUNG_IDX:
            lead = _CHO_IDX[c]
            vowel = _JUNG_IDX[s[i + 1]]
            i += 2
            tail = 0
            # 받침 후보: 단, 다음 글자가 (자음+모음)으로 다음 음절을 시작하면 그쪽 초성.
            if (
                i < n
                and s[i] in _JONG_IDX
                and not (i + 1 < n and s[i] in _CHO_IDX and s[i + 1] in _JUNG_IDX)
            ):
                tail = _JONG_IDX[s[i]]
                i += 1
            out.append(chr(0xAC00 + (lead * 21 + vowel) * 28 + tail))
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _mask_whitelist(s: str) -> str:
    """학술·중립어(始發點/始發驛/始發地)의 '시발' 만 동일 길이 토큰으로 가려 어간 오탐을 막는다.
    길이를 보존하므로 원문 기준 span(start/end)은 그대로 유효하고, 가려진 위치는 실제 욕설이
    아니라 매칭에 영향 없다. _TOX_WHITELIST 가 lookahead 한정이라 단일 패스로 O(n)."""
    return _TOX_INTENSIFIER_OK.sub(_TOX_WHITELIST_MASK, _TOX_WHITELIST.sub(_TOX_WHITELIST_MASK, s))


def scan_toxicity(text: str) -> list[Violation]:
    out: list[Violation] = []
    collapsed = _TOX_SEP.sub("", text)
    variants = [text] if collapsed == text else [text, collapsed]
    # 완전분해 호환자모 우회(ㄱ.ㅐ.ㅅ.ㅐ.…): 자모 사이 기호 제거 → 완성형 재결합본 추가.
    jamo_collapsed = _TOX_SEP_JAMO.sub("", text)
    recombined = _recombine_jamo(jamo_collapsed)
    if recombined not in variants:
        variants.append(recombined)
    # 자모↔완성형 경계의 숫자/기호(ㅅ1발) 걷어내 'ㅅ발' 재결합 → 초성ㅅ+발 변형이 잡히게.
    boundary = _TOX_SEP_JAMO_BOUNDARY.sub("", text)
    if boundary not in variants:
        variants.append(boundary)
    # 모음늘임 우회(시바아아/시이이발) → 시바/시발 로 축약본 추가.
    stretched = _collapse_vowel_stretch(text)
    if stretched not in variants:
        variants.append(stretched)
    # 어간 매칭용 사본: 학술·중립어(始發點 등)만 가린다(길이 보존 → 원문 span 유효).
    masked = [_mask_whitelist(v) for v in variants]
    for code, pat, sev in (
        ("profanity", _PROFANITY, Severity.MEDIUM),
        ("profanity", _TRANSLIT_PROFANITY, Severity.MEDIUM),
        ("profanity", _ROMAN_PROFANITY, Severity.MEDIUM),
        ("profanity", _EN_PROFANITY, Severity.MEDIUM),
        ("hate_speech", _HATE, Severity.HIGH),
    ):
        for idx, mv in enumerate(masked):
            m = pat.search(mv)
            if not m:
                continue
            orig = variants[idx] is text
            # 매칭은 마스킹 사본에서 했지만, 보고 텍스트는 원문(가려진 건 실제 욕설 아님).
            matched = text[m.start():m.end()] if orig else m.group(0)
            out.append(
                Violation(
                    code=code,
                    category=Category.TOXICITY,
                    severity=sev,
                    reason=f"toxic language in output: {code}",
                    start=m.start() if orig else None,
                    end=m.end() if orig else None,
                    matched=matched,
                )
            )
            break  # 같은 사전은 원본/사본 중 한 번만 보고
    return out
