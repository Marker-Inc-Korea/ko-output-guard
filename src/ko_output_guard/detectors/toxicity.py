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
    r"씨발|시발|씨바|씨밸|씨벌|씨빨|시팔|개새끼|개색기|좆|졷같|좃같|존나|병신|븅신|빙신|뷁신|"
    r"지랄|꺼져|엿\s*먹|닥쳐|"
    r"새끼야|개자식|미친놈|미친년|호로(?:새끼|자식|놈|년)|쌍놈|썅|뒤져|디져|씨불|개색|"
    # 초성/분리 변형(공백 삽입 우회 포함) — ㅅㅂ/ㅆㅂ/ㅂㅅ, ㅈㄹ, ㄲㅈ(꺼져), ㅄ
    r"ㅅ\s*ㅂ|ㅆ\s*ㅂ|ㅂ\s*ㅅ|ㅄ|ㅈ\s*ㄹ|ㄲ\s*ㅈ|"
    # 받침 분리 우회(완성음절+단독 종성) — 정규화로 안 펴지는 흔한 변형
    r"시바\s*ㄹ|지라\s*ㄹ|병시\s*ㄴ|조\s*ㅈ\s*같|미친노\s*ㅁ|미친녀\s*ㄴ|쌍노\s*ㅁ|개자시\s*ㄱ"
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
    r"틀딱|급식충|맘충|한남충|한녀충|페미충|냄저|보슬아치|잼민이|김치녀|김치남|짱깨|쪽바리|흑형|상폐녀")

# 욕설 은닉용 '글자 사이' 기호/이모지/숫자 제거(검사 전용 사본). 한글 음절 사이의
# 구분 기호(씨~발/씨:발/씨(발)), 이모지(씨🤬발), 숫자(시1발)를 걷어내 어간을 복원한다.
_TOX_SEP = re.compile(
    r"(?<=[가-힣])"
    r"[\s~:=+^*|/!?@#$%&._,·‧\-()\[\]{}<>\d☀-➿\U0001f000-\U0001faff]+"
    r"(?=[가-힣])"
)

# 완전분해 호환자모(ㄱ.ㅐ.ㅅ.ㅐ.…)는 위 lookaround(가-힣)에 안 걸린다. 호환자모(ㄱ-ㅣ,
# U+3131~U+3163) 사이의 구분 기호만 걷어내는 두 번째 collapse 패스. 이모지/숫자까지는
# 넣지 않는다(자모 나열 자체가 드물고, 분해형 욕설 우회 신호이므로 기호/공백이면 충분).
_TOX_SEP_JAMO = re.compile(
    r"(?<=[ㄱ-ㅣ])"
    r"[\s~:=+^*|/!?@#$%&._,·‧\-()\[\]{}<>]+"
    r"(?=[ㄱ-ㅣ])"
)

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


def scan_toxicity(text: str) -> list[Violation]:
    out: list[Violation] = []
    collapsed = _TOX_SEP.sub("", text)
    variants = [text] if collapsed == text else [text, collapsed]
    # 완전분해 호환자모 우회(ㄱ.ㅐ.ㅅ.ㅐ.…): 자모 사이 기호 제거 → 완성형 재결합본 추가.
    jamo_collapsed = _TOX_SEP_JAMO.sub("", text)
    recombined = _recombine_jamo(jamo_collapsed)
    if recombined not in variants:
        variants.append(recombined)
    for code, pat, sev in (
        ("profanity", _PROFANITY, Severity.MEDIUM),
        ("profanity", _ROMAN_PROFANITY, Severity.MEDIUM),
        ("profanity", _EN_PROFANITY, Severity.MEDIUM),
        ("hate_speech", _HATE, Severity.HIGH),
    ):
        for v in variants:
            m = pat.search(v)
            if not m:
                continue
            orig = v is text
            out.append(
                Violation(
                    code=code,
                    category=Category.TOXICITY,
                    severity=sev,
                    reason=f"toxic language in output: {code}",
                    start=m.start() if orig else None,
                    end=m.end() if orig else None,
                    matched=m.group(0),
                )
            )
            break  # 같은 사전은 원본/사본 중 한 번만 보고
    return out
