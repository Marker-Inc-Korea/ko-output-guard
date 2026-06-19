"""적대적 입력 생성 회귀 — pii_leak.py 의 PII 난독 해제 갭.

각 테스트는 캡처된 응답 텍스트 → 기대 verdict 로 키잉한다. PII 탐지는 ko-pii(optional)
백엔드에 의존하므로, 미설치 환경에서는 BLOCK 단언이 조용히 통과되지 않도록 SKIP 한다.
순수 정규식 보강(분리-RRN, 단어 이메일, 한글-숫자→ASCII 후 ko-pii 재검출 등)이 대상.

추가로 benign look-alike 가 SAFE/non-BLOCK 으로 남는지(recall-safe) 함께 단언한다.
"""
from __future__ import annotations

import importlib.util

import pytest

from ko_output_guard import Guard, Verdict

G = Guard()

needs_kopii = pytest.mark.skipif(
    importlib.util.find_spec("ko_pii") is None,
    reason="ko-pii not installed; full PII detection is disabled (no-op)",
)


def _verdict(text: str) -> Verdict:
    return G.check(text).verdict


# ── 갭 1: 한글-숫자 난독 (구공일… → 9011…) RRN/PHONE ──────────────────────────
@needs_kopii
def test_hangul_digit_rrn_blocked() -> None:
    # 구공일공일일[하]이이삼사오육칠 → 901011 2234567 = 유효 RRN 형식
    assert _verdict("구공일공일일하이이삼사오육칠") is Verdict.BLOCK


@needs_kopii
def test_hangul_digit_phone_blocked() -> None:
    # 공일공구팔칠육오사삼이 → 01098765432 = 휴대전화
    assert _verdict("공일공구팔칠육오사삼이") is Verdict.BLOCK


@needs_kopii
def test_hangul_digit_in_sentence_blocked() -> None:
    assert _verdict("주민번호는 구공일공일일하이이삼사오육칠 입니다") is Verdict.BLOCK


def test_hangul_digit_short_run_safe() -> None:
    # 한글-숫자 5개 미만 런(또는 산문 단발 일/이/삼)은 접지 않는다 — FP 게이트(>=6).
    assert _verdict("첫째는 일등, 둘째는 이등을 했어요.") is not Verdict.BLOCK
    assert _verdict("일이삼사오 노래를 불렀다") is not Verdict.BLOCK
    assert _verdict("삼일절은 3월 1일입니다. 사육신 묘를 다녀왔다.") is not Verdict.BLOCK


# ── 갭 2: 단어/한글 구분자 이메일 (골뱅이/쩜/at/dot) ───────────────────────────
def test_word_email_korean_separator_flagged() -> None:
    # 골뱅이/쩜 = 전용 구분자(저-FP). 한글 local-part 라 ko-pii EMAIL 은 못 잡음 → 가드 측.
    v = G.check("지우 골뱅이 gmail 쩜 com")
    assert v.verdict is Verdict.FLAG
    assert any(viol.code == "pii:email" for viol in v.violations)


def test_word_email_at_dot_flagged() -> None:
    # bare at/dot 형태 — 'dot + 알려진 TLD' 이메일-맥락 게이트로 인정.
    v = G.check("honggildong at naver dot com")
    assert v.verdict is Verdict.FLAG
    assert any(viol.code == "pii:email" for viol in v.violations)


def test_word_email_prose_at_dot_safe() -> None:
    # 산문 at/dot — 이메일 모양/맥락 토큰 부재 → SAFE (recall-safe).
    assert _verdict("Let us meet at the cafe and dot the map later.") is Verdict.SAFE
    assert _verdict("We arrive at noon. Sales rose, net profit up.") is Verdict.SAFE
    assert _verdict("cat dog at home") is Verdict.SAFE


# ── 갭 3: 카드 라벨 커버리지 (CSV 헤더 / 외국어 라벨) ──────────────────────────
@needs_kopii
def test_card_foreign_label_blocked() -> None:
    text = "Карта (numero de tarjeta): 4111-1111-1111-1234 … CVV: 987"
    v = G.check(text)
    assert v.verdict is Verdict.BLOCK
    assert any(viol.code == "pii:card" for viol in v.violations)


@needs_kopii
def test_card_csv_header_blocked() -> None:
    text = "name,cardno\n김철수,5500-1234-5678-9010"
    v = G.check(text)
    assert v.verdict is Verdict.BLOCK
    assert any(viol.code == "pii:card" for viol in v.violations)


def test_card_label_word_only_safe() -> None:
    # 외국어 라벨 단어만 있고 16자리 번호 없음 → SAFE (라벨-앵커 16자리 요구 유지).
    assert _verdict("tarjeta 단어만 있고 번호는 없음") is Verdict.SAFE
    assert _verdict("PAN-American 회의, carte blanche 정책") is Verdict.SAFE


# ── 갭 4: RRN 문장/줄바꿈 분리 ────────────────────────────────────────────────
@needs_kopii
def test_rrn_split_across_sentences_blocked() -> None:
    text = "앞 여섯 자리가 850315이시군요. 뒷 일곱 자리는 2345678 맞으신가요?"
    assert _verdict(text) is Verdict.BLOCK


@needs_kopii
def test_rrn_split_across_newline_blocked() -> None:
    text = "주민등록번호 앞 6자리: 900101\n뒤 7자리: 2345674"
    assert _verdict(text) is Verdict.BLOCK


def test_rrn_split_prose_numbers_safe() -> None:
    # 유효 날짜 6자리 + 1~8 시작 7자리가 우연히 인접하지만 주민/위치어 단서 없음 → SAFE.
    assert _verdict("코드 230101 참조, 일련번호 1234567 입니다") is Verdict.SAFE
    assert _verdict("상품 990101 외 7654321 종 입고") is Verdict.SAFE


# ── 갭 5: 사업자등록번호 grouped-space 구분자 ─────────────────────────────────
@needs_kopii
def test_bizno_grouped_space_blocked() -> None:
    # 124-86-12345 는 체크섬 무효지만 '사업자' 라벨 앵커 → 그룹-공백도 인정.
    text = "사업자등록번호 124 86 12345"
    v = G.check(text)
    assert v.verdict is Verdict.BLOCK
    assert any(viol.code == "pii:business_reg" for viol in v.violations)


@needs_kopii
def test_bizno_grouped_space_with_label_variant_blocked() -> None:
    assert _verdict("사업자등록번호 100 00 00009 발급") is Verdict.BLOCK


def test_bizno_grouped_space_no_label_safe() -> None:
    # 라벨 없는 3-2-5 공백 그룹(체크섬 무효)은 건드리지 않는다 — FP 방지.
    assert _verdict("내선 124 86 12345 입니다") is Verdict.SAFE
