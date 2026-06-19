"""PII 재누출 탐지 — ko-pii 를 재사용한다(설치돼 있으면). 출력 텍스트에 주민/카드/
전화/이메일 등 개인정보가 들어가면 누출로 본다.

ko-pii 미설치 환경에서도 import 가 실패하지 않도록 lazy + graceful 하게 처리한다.
다만 *조용히* 강등되면 PII 누출이 통과되는 걸 호출자가 모르므로, strict 모드는
예외를 던지고, 아니면 1회 WARN 로그 + degraded 플래그로 알린다.
"""
from __future__ import annotations

import logging
import re

from ..result import Category, Severity, Violation

_log = logging.getLogger("ko_output_guard")
# 강등 경고는 프로세스당 1회만(로그 폭주 방지). 재시도 시 다시 알리지 않는다.
_DEGRADED_WARNED = False


class PIIBackendUnavailable(RuntimeError):
    """strict 모드에서 ko-pii(PII 백엔드)가 없을 때 발생 — 조용한 강등을 막는다."""


def pii_backend_available() -> bool:
    """ko-pii(전체 PII 탐지 백엔드)를 import 할 수 있는지. 부분 RRN 정규식은 백엔드와
    무관하게 항상 동작하므로, 이 값이 False 면 '부분 탐지만 가능한 강등 상태'를 뜻한다."""
    try:
        import ko_pii  # noqa: F401
    except ImportError:
        return False
    return True

# 심각도 매핑(ko-pii RiskLevel → output-guard Severity).
_RISK_TO_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}

# 연결 문자열 user:pw@host — 여기 '@host' 는 이메일이 아니라 DB/서비스 호스트다.
_CONN_USERINFO = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s/@]*:[^\s/@]*@[^\s/@]+")

# 구분자 우회 회복용 — 사본에서 걷어내는 문자(공백/탭/콤마/세미콜론/언더스코어, 전각 포함).
_STRIP_CHARS = frozenset(" \t,;_，；＿")

# 출력 가드에서 제외하는 ko-pii 라벨. PERSON/ADDRESS/PERSONAL_ATTR 은 성씨-시작
# 일반명사 오탐이 잦고, MAJOR(전공)은 '의학/약학/화학', AGE('두 살')는 맥락 의존
# 일반표현이라 단독으로는 식별이 안 되므로 결정적 PII(RRN/카드/전화/이메일/사업자)만 본다.
_EXCLUDE = {"PERSON", "ADDRESS", "PERSONAL_ATTR", "MAJOR", "AGE"}

# 비-개인 번호 맥락 — 운송장/주문/팩스 등은 전화 형식이어도 개인정보가 아니다.
_NONPERSONAL_NUM_CTX = re.compile(
    r"운송장|송장|주문\s*번호|택배|등기|배송\s*번호|상품\s*코드|일련\s*번호|"
    r"팩스|대표\s*(?:번호|전화)|고객\s*센터")

# 할루시네이션 카드번호 보강 — ko-pii CARD 는 Luhn+BIN 을 강제하므로, LLM 이 지어낸
# (체크섬 무효) 카드번호는 통과한다. '카드번호/신용카드/credit card' 같은 카드 맥락
# 라벨이 명시되면, 라벨 근처의 16자리(대시/공백/연속) 숫자를 Luhn 무관하게 pii:card 로
# 잡는다(BLOCK). 라벨이 없으면 bare 16자리는 건드리지 않는다 — 주문번호/일련번호 FP 방지.
_CARD_LABEL = re.compile(
    r"카드\s*번호|신용\s*카드|체크\s*카드|카드\s*결제|결제\s*카드|"
    r"credit\s*card|creditCard|debit\s*card|"
    # CSV/코드 헤더(cardno/card_no/card_num/pan) + 외국어 라벨(러/스/불/독) 보강.
    r"card\s*no|card_no|card_num|cardnum|\bpan\b|"
    r"Карта|tarjeta|numero\s*de\s*tarjeta|carte\s*(?:de\s*)?cr[eé]dit|kreditkarte",
    re.IGNORECASE)
# 16자리: 4-4-4-4(대시/공백/점 구분) 또는 연속 16자리. 앞뒤 숫자 경계로 더 긴 숫자열 배제.
_CARD_16 = re.compile(
    r"(?<![0-9])(?:[0-9]{4}[-. ][0-9]{4}[-. ][0-9]{4}[-. ][0-9]{4}|[0-9]{16})(?![0-9])")
# 라벨↔숫자 근접 윈도(문자 수). 라벨이 같은 문장/근처에 있을 때만 발동(원거리 우연 매칭 방지).
_CARD_CTX_WINDOW = 40

# 할루시네이션 사업자등록번호 보강 — ko-pii BUSINESS_REG 는 국세청 체크섬을 강제하므로,
# LLM 이 지어낸(체크섬 무효) 번호는 통과한다. '사업자(등록)번호' 라벨이 명시되면, 라벨
# 근처의 NNN-NN-NNNNN 을 체크섬 무관하게 pii:business_reg 로 잡는다(BLOCK). 라벨이 없으면
# 건드리지 않는다(임의 3-2-5 숫자열 FP 방지).
# '사업자' 단독도 맥락으로 인정한다(요구사항: '사업자/사업자등록번호' context). 'NNN-NN-NNNNN'
# 형식 자체가 매우 한정적이라 라벨을 '사업자'까지 넓혀도 FP 가 거의 없다(recall-safe).
_BIZNO_LABEL = re.compile(r"사업자")
# 3-2-5 그룹. 구분자는 하이픈 또는 단일 공백(grouped-space) 허용 — '124 86 12345'.
# 체크섬 무관(라벨 앵커)이지만, 그룹 길이(3·2·5)와 그룹별 단일 구분자 강제로 임의
# 숫자열 FP 를 막는다(자리별 공백 '1 2 4 ...'는 기존 spacing-evasion 경로가 담당).
_BIZNO = re.compile(r"(?<![0-9])([0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{5})(?![0-9])")
_BIZNO_CTX_WINDOW = 40


def _scan_card_context(text: str) -> list[Violation]:
    """카드 맥락 라벨 근처의 16자리 숫자 → pii:card (Luhn 무효여도). 할루시 카드 누출 보강."""
    out: list[Violation] = []
    label_spans = [(m.start(), m.end()) for m in _CARD_LABEL.finditer(text)]
    if not label_spans:
        return out
    seen: set[tuple[int, int]] = set()
    for m in _CARD_16.finditer(text):
        s, e = m.start(), m.end()
        # 16자리 숫자가 카드 라벨 근처(앞 윈도)에 있어야 발동.
        if not any(0 <= s - le < _CARD_CTX_WINDOW or 0 <= ls - e < _CARD_CTX_WINDOW
                   for ls, le in label_spans):
            continue
        if (s, e) in seen:
            continue
        seen.add((s, e))
        out.append(Violation(
            code="pii:card", category=Category.PII_LEAK, severity=Severity.HIGH,
            reason="card number near card-context label (checksum-independent)",
            start=s, end=e, matched=m.group(0)[:40],
        ))
    return out


def _scan_bizno_context(text: str) -> list[Violation]:
    """사업자(등록)번호 라벨 근처의 NNN-NN-NNNNN → pii:business_reg (체크섬 무효여도)."""
    out: list[Violation] = []
    label_spans = [(m.start(), m.end()) for m in _BIZNO_LABEL.finditer(text)]
    if not label_spans:
        return out
    seen: set[tuple[int, int]] = set()
    for m in _BIZNO.finditer(text):
        s, e = m.start(1), m.end(1)
        if not any(0 <= s - le < _BIZNO_CTX_WINDOW or 0 <= ls - e < _BIZNO_CTX_WINDOW
                   for ls, le in label_spans):
            continue
        if (s, e) in seen:
            continue
        seen.add((s, e))
        out.append(Violation(
            code="pii:business_reg", category=Category.PII_LEAK, severity=Severity.HIGH,
            reason="business registration number near label (checksum-independent)",
            start=s, end=e, matched=m.group(1)[:40],
        ))
    return out


# 부분 주민등록번호 — ko-pii 는 전체(6-7) 만 잡으므로, '주민(등록)번호' 라벨 근처의
# 뒷자리 7자리 또는 앞 6자리 단독 누출을 보강한다. 임의 6/7자리 숫자가 아니라
# *주민번호 라벨이 명시*된 경우만 잡아 통계/코드 오탐을 막는다(recall-safe).
_RRN_LABEL = r"주민\s*(?:등록)?\s*번호|주민번호|주민등록번호"
# 라벨과 숫자 사이에 끼어드 수 있는 위치어구('뒷자리','앞 6자리','뒤 7자리','끝' 등).
# '6자리/7자리' 안의 한 자리 숫자는 RRN 본체가 아니므로 gap 으로 흡수한다(라벨 한정 유지).
_RRN_GAP = r"(?:[^0-9\n]|[0-9]\s*자리)"
# 뒷자리 7자리: 성별코드(1~8) 시작 + 6자리. '뒷자리/뒤/끝/마지막' 위치어 허용.
_RRN_BACK = re.compile(
    rf"(?:{_RRN_LABEL})(?:{_RRN_GAP}){{0,14}}?(?<![0-9])([1-8][0-9]{{6}})(?![0-9])")
# 앞 6자리: YYMMDD. '앞/앞자리/생년월일'식 위치어 또는 주민번호 라벨 근처 6자리.
_RRN_FRONT = re.compile(
    rf"(?:{_RRN_LABEL})(?:{_RRN_GAP}){{0,14}}?(?<![0-9])([0-9]{{2}}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01]))(?![0-9-])")


def _scan_partial_rrn(text: str) -> list[Violation]:
    """'주민(등록)번호' 라벨 + 뒷 7자리 또는 앞 6자리(YYMMDD) 단독 누출."""
    out: list[Violation] = []
    seen: set[tuple[int, int]] = set()
    for pat, code, reason in (
        (_RRN_BACK, "pii:rrn_partial_back", "partial RRN (back 7 digits) in output"),
        (_RRN_FRONT, "pii:rrn_partial_front", "partial RRN (front 6 digits) in output"),
    ):
        for m in pat.finditer(text):
            s, e = m.start(1), m.end(1)
            if (s, e) in seen:
                continue
            seen.add((s, e))
            out.append(
                Violation(
                    code=code, category=Category.PII_LEAK, severity=Severity.HIGH,
                    reason=reason, start=s, end=e, matched=m.group(1)[:40],
                )
            )
    return out


# ── RRN 문장/줄바꿈 분리 누출 ──────────────────────────────────────────────
# '앞 여섯 자리가 850315 ... 뒷 일곱 자리는 2345678' / '앞 6자리: 900101\n뒤 7자리: 2345674'
# 처럼 앞 6자리(YYMMDD)와 뒤 7자리(성별 1~8 + 6)가 문장·줄바꿈으로 갈라져도 한 쌍이면
# 사실상 완전한 주민번호다. 앞6=유효날짜, 뒤7=성별코드 시작 두 게이트로 산문 FP 를 0 에
# 가깝게 막는다. 사이 filler 는 줄바꿈 포함 짧은 윈도로 제한(원거리 우연 결합 방지).
_RRN_FRONT_BODY = r"[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])"
_RRN_BACK_BODY = r"[1-8][0-9]{6}"
# filler: 줄바꿈 1개까지 허용, 숫자는 불허(다른 숫자열이 끼면 결합 안 함), 길이 cap.
_RRN_SPLIT = re.compile(
    rf"(?<![0-9])({_RRN_FRONT_BODY})(?![0-9])(?P<gap>[^0-9]{{1,24}}?)(?<![0-9])({_RRN_BACK_BODY})(?![0-9])")
# 주민번호 분리 누출의 맥락 단서 — '주민(번호)'/위치어('앞/뒤/여섯/일곱/6자리/7자리').
# 유효 날짜 6자리 + 성별코드 7자리만으로는 우연한 숫자 인접(온도/무게/코드) FP 가 있어,
# 한 쌍의 윈도 안에 이 단서가 있을 때만 분리-RRN 으로 인정한다(recall-safe).
_RRN_SPLIT_CUE = re.compile(
    r"주민|앞|뒤|뒷|여섯|일곱|6\s*자리|7\s*자리|자리|생년월일")


def _scan_rrn_split(text: str) -> list[Violation]:
    """앞 6자리(YYMMDD) + 뒤 7자리(성별+6)가 문장/줄바꿈으로 갈라진 주민번호 누출.

    유효 날짜 + 성별코드 두 게이트에 더해, 앞6 직전(짧은 윈도) 또는 사이 filler 에 주민/
    위치어 단서가 있을 때만 인정해 산문 숫자 인접 FP 를 막는다."""
    out: list[Violation] = []
    for m in _RRN_SPLIT.finditer(text):
        pre = text[max(0, m.start(1) - 24):m.start(1)]
        if not (_RRN_SPLIT_CUE.search(pre) or _RRN_SPLIT_CUE.search(m.group("gap"))):
            continue
        out.append(Violation(
            code="pii:rrn_split", category=Category.PII_LEAK, severity=Severity.HIGH,
            reason="RRN split across sentence/newline (front 6 + back 7)",
            start=m.start(1), end=m.end(2),
            matched=(m.group(1) + "-" + m.group(2))[:40],
        ))
    return out


# ── 한글-숫자 난독 해제 (구공일일… → 9011…) ───────────────────────────────────
# jailbreak 출력이 주민/전화번호를 한글 수사(공/영/일/이/…/구)로 흩뜨릴 수 있다.
# 6자리 이상 '연속 한글-숫자 런'에서만 ASCII 로 접어(prose 의 '일/이/삼' 단발 FP 방지),
# RRN/PHONE 검출기에 재투입한다. filler(런 사이 1~2자 비숫자한글/공백)는 흡수.
_HANGUL_DIGIT = {
    "공": "0", "영": "0", "일": "1", "이": "2", "삼": "3", "사": "4",
    "오": "5", "육": "6", "칠": "7", "팔": "8", "구": "9",
}
# 런: 한글-숫자(필수) + 그 사이의 짧은 filler(비숫자, 줄바꿈 제외, 한글-숫자 아닌 1~2자).
_HD_CHARS = "".join(_HANGUL_DIGIT)
_HD_RUN = re.compile(
    rf"[{_HD_CHARS}](?:[^0-9\n]{{0,2}}?[{_HD_CHARS}]){{5,}}")


def _scan_hangul_digit_pii(text: str) -> list[Violation]:
    """한글-숫자 런(>=6)을 ASCII 로 접어 RRN/PHONE 만 재검출. ko-pii 없으면 no-op."""
    if not _HD_RUN.search(text):
        return []
    try:
        from ko_pii import detect_all
    except ImportError:
        return []
    out: list[Violation] = []
    for run in _HD_RUN.finditer(text):
        seg = run.group(0)
        # 런 내부에서 한글-숫자만 ASCII 로 모으고, 사본 idx→원본 idx 역매핑 구축.
        folded_chars: list[str] = []
        idx_map: list[int] = []
        base = run.start()
        for i, ch in enumerate(seg):
            d = _HANGUL_DIGIT.get(ch)
            if d is not None:
                folded_chars.append(d)
                idx_map.append(base + i)
        if len(folded_chars) < 6:
            continue
        folded = "".join(folded_chars)
        for d in detect_all(folded, include=("RRN", "PHONE")):
            risk = getattr(getattr(d, "risk_level", None), "name", "MEDIUM")
            out.append(Violation(
                code=f"pii:{d.label.lower()}", category=Category.PII_LEAK,
                severity=_RISK_TO_SEV.get(risk, Severity.MEDIUM),
                reason=f"personal data via Hangul-digit obfuscation: {d.label}",
                start=idx_map[d.start], end=idx_map[d.end - 1] + 1,
                matched=d.text[:40],
            ))
    return out


# ── 단어/한글 구분자 이메일 난독 해제 (지우 골뱅이 gmail 쩜 com) ────────────────
# 골뱅이/앳/at → @, 쩜/점/dot → .  로 복원한 뒤 이메일 모양을 직접 매칭한다(ko-pii EMAIL
# 은 ASCII local-part 만 잡아 '지우@…' 한글 로컬파트를 놓치므로 가드 측에서 직접 검출).
# 골뱅이/쩜/점 은 전용 구분자라 저-FP. bare 'at'/'dot' 은 산문 FP 위험이 커, 같은 후보
# 토큰열 안에 골뱅이/앳 계열 @-구분자가 함께 있을 때(=이메일 맥락)만 인정한다.
_EMAIL_LOCAL = r"[0-9A-Za-z가-힣._%+\-]{1,64}"
_EMAIL_DOMAIN_LABEL = r"[0-9A-Za-z가-힣\-]{1,63}"
# 강한 @-구분자(골뱅이/앳) — 전용 구분자라 저-FP. bare 'at' 은 산문 FP 위험.
_AT_WORD = r"골뱅이|앳|at"
_DOT_WORD = r"쩜|점|dot"
_SEP = r"[\s()\[\]<>]*"
# 흔한 TLD — bare 'at/dot' 형태의 이메일-맥락 게이트(산문 FP 차단).
_TLD = (r"com|net|org|co\.kr|kr|io|gov|edu|ac\.kr|or\.kr|go\.kr|"
        r"co|biz|info|me|dev|app|ai")
# local <at> domain <dot> tld — 구분자 단어는 공백/괄호로 둘러싸일 수 있음. 마지막
# 라벨(TLD)을 그룹 캡처해 게이트 검사에 사용.
_WORD_EMAIL = re.compile(
    rf"(?<![0-9A-Za-z가-힣@.])({_EMAIL_LOCAL}){_SEP}(?:{_AT_WORD}){_SEP}"
    rf"({_EMAIL_DOMAIN_LABEL})(?:{_SEP}(?:{_DOT_WORD}){_SEP}({_EMAIL_DOMAIN_LABEL}))+",
    re.IGNORECASE)
_STRONG_AT = re.compile(r"골뱅이|앳", re.IGNORECASE)
_TLD_TAIL = re.compile(rf"(?:{_DOT_WORD})\s*(?:{_TLD})\b", re.IGNORECASE)


def _scan_word_email(text: str) -> list[Violation]:
    """'골뱅이/쩜/at/dot' 단어 구분자로 흩뜨린 이메일 복원·검출.

    골뱅이/앳(전용 @-구분자)이 있으면 그대로 인정. bare 'at'/'dot' 만으로 된 매칭은
    산문 FP 위험이 커, '쩜/점/dot + 알려진 TLD'(=이메일 맥락 토큰)로 끝날 때만 인정한다.
    """
    out: list[Violation] = []
    for m in _WORD_EMAIL.finditer(text):
        span = m.group(0)
        if not (_STRONG_AT.search(span) or _TLD_TAIL.search(span)):
            continue
        out.append(Violation(
            code="pii:email", category=Category.PII_LEAK, severity=Severity.MEDIUM,
            reason="email via word-separator obfuscation (골뱅이/쩜/at/dot)",
            start=m.start(), end=m.end(),
            matched=span[:40],
        ))
    return out


def scan_pii_leak(text: str, *, strict: bool = False) -> list[Violation]:
    # 부분 주민번호(뒷 7 / 앞 6) + 라벨-앵커 카드/사업자번호는 순수 정규식이라 ko-pii
    # 미설치여도 잡는다 — 라벨이 명시된 경우만이므로 비식별 자체가 결정적. 먼저 수집해
    # 두고, ko-pii 가 같은 구간을 이미(전체 RRN/유효 카드/유효 사업자번호로) 잡았으면 중복 제거.
    partial = _scan_partial_rrn(text)
    partial += _scan_card_context(text)
    partial += _scan_bizno_context(text)
    partial += _scan_rrn_split(text)      # 문장/줄바꿈 분리 RRN (순수 정규식)
    partial += _scan_word_email(text)     # 골뱅이/쩜/at/dot 이메일 (순수 정규식)
    try:
        from ko_pii import detect_all
    except ImportError as exc:
        # 조용히 강등하지 않는다. strict 면 예외, 아니면 1회 WARN + 부분 탐지만.
        if strict:
            raise PIIBackendUnavailable(
                "ko-pii not installed: full PII leak detection is unavailable. "
                "Install ko-pii or disable strict mode."
            ) from exc
        global _DEGRADED_WARNED
        if not _DEGRADED_WARNED:
            _log.warning(
                "ko-pii not installed: PII leak detection is DEGRADED "
                "(only label-anchored partial RRN is checked). GuardResult.degraded=True."
            )
            _DEGRADED_WARNED = True
        return partial  # ko-pii 미설치 → 부분 RRN 만 보강(다른 detector 는 계속)
    conn_spans = [(m.start(), m.end()) for m in _CONN_USERINFO.finditer(text)]
    out: list[Violation] = []
    kopii_spans: list[tuple[int, int]] = []
    for d in detect_all(text, exclude=_EXCLUDE):
        # 연결 문자열 내부의 '이메일'은 실제로는 호스트이므로 제외(과탐 방지).
        if d.label == "EMAIL" and any(s <= d.start < e for s, e in conn_spans):
            continue
        # 운송장/주문/팩스 등 비-개인 번호 맥락의 '전화'는 제외.
        if d.label == "PHONE" and _NONPERSONAL_NUM_CTX.search(text[max(0, d.start - 12):d.start]):
            continue
        kopii_spans.append((d.start, d.end))
        risk = getattr(getattr(d, "risk_level", None), "name", "MEDIUM")
        out.append(
            Violation(
                code=f"pii:{d.label.lower()}",
                category=Category.PII_LEAK,
                severity=_RISK_TO_SEV.get(risk, Severity.MEDIUM),
                reason=f"personal data in output: {d.label}",
                start=d.start,
                end=d.end,
                matched=d.text[:40],
            )
        )
    # 자리/구분자 우회('9 0 0 1…', '900101,1234567', '900101_1234567') 회복 — 공백·콤마·
    # 세미콜론·언더스코어(전각 포함)를 걷어낸 사본에서 재검사한다. checksum·형식 검증이 있어
    # 임의 숫자 나열은 통과 못 한다. 사본 인덱스→원본 인덱스 역매핑(idx_map)으로 원본 span 을
    # 복원해, BLOCK 시 redacted_text 가 PII 를 정확히 마스킹하도록 한다(재누출 방지).
    collapsed_chars: list[str] = []
    idx_map: list[int] = []
    for i, ch in enumerate(text):
        if ch not in _STRIP_CHARS:
            collapsed_chars.append(ch)
            idx_map.append(i)
    collapsed = "".join(collapsed_chars)
    if collapsed != text:
        for d in detect_all(collapsed, exclude=_EXCLUDE):
            # 전화는 자리별 공백이 정상 표기('010 1234 5678')와 구분되지 않아 사본 회복에서 제외.
            if d.label in ("EMAIL", "PHONE") or d.text in text:
                continue  # 이메일/전화 오탐·원본에 그대로 있는 건 제외(중복 방지)
            risk = getattr(getattr(d, "risk_level", None), "name", "MEDIUM")
            out.append(
                Violation(
                    code=f"pii:{d.label.lower()}",
                    category=Category.PII_LEAK,
                    severity=_RISK_TO_SEV.get(risk, Severity.MEDIUM),
                    reason=f"personal data via spacing-evasion: {d.label}",
                    start=idx_map[d.start],          # 원본 span 복원
                    end=idx_map[d.end - 1] + 1,
                    matched=d.text[:40],
                )
            )
    # 한글-숫자 난독(구공일… → 9011…) RRN/PHONE — ko-pii 가 필요하므로 import 성공 후 실행.
    for v in _scan_hangul_digit_pii(text):
        out.append(v)
        if v.start is not None and v.end is not None:
            kopii_spans.append((v.start, v.end))
    # 부분 RRN 보강 — ko-pii 가 같은 구간을 (전체 RRN 등으로) 이미 잡았으면 중복 제거.
    for v in partial:
        if v.start is None or v.end is None:
            out.append(v)
            continue
        if not any(s <= v.start and v.end <= e for s, e in kopii_spans):
            out.append(v)
    # 이메일 단건은 MEDIUM(설계상 FLAG)이지만, 한 응답에 서로 다른 이메일이 3개 이상이면
    # 연락처 일괄 누출(명단 덤프) 신호이므로 HIGH 집계 위반을 1개 추가해 BLOCK 으로 승격한다.
    # 같은 주소 반복은 1개로 센다(distinct). 전화는 대표번호/안내 등 비-개인 비중이 커 제외.
    distinct_emails = {
        (v.matched or "").lower()
        for v in out
        if v.code == "pii:email" and v.matched
    }
    if len(distinct_emails) >= 3:
        out.append(Violation(
            code="pii:email_bulk", category=Category.PII_LEAK, severity=Severity.HIGH,
            reason=f"bulk email leak: {len(distinct_emails)} distinct emails in one output",
        ))
    return out
