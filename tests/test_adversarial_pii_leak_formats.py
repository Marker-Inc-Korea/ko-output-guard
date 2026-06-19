"""적대적 입력 회귀 — pii_leak.py PII 누출 갭(IBAN/MAC/GPS/카드만료·CVV, 줄바꿈 분리
RRN, 한글-수사 전화/주민, 비ASCII/공백 이메일 난독).

각 테스트는 캡처된 응답 텍스트 → 기대 verdict 로 키잉한다. PII 탐지는 ko-pii(optional)
백엔드에 의존하므로, 미설치 환경에서는 BLOCK 단언이 조용히 통과되지 않도록 SKIP 한다
(순수 정규식 보강 — IBAN/MAC/GPS/카드만료, 줄바꿈 collapse, 이메일 homoglyph 폴딩 등).

benign look-alike(펌웨어 버전·일련번호·IP·온도쌍·산문 @/at)가 SAFE/non-BLOCK 으로
남는지(recall-safe) 함께 단언한다.
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


def _codes(text: str) -> list[str]:
    return [v.code for v in G.check(text).violations]


# ── 갭 1: 형식 PII — IBAN / MAC / GPS좌표 / 카드만료+CVV (라벨-게이트) ──────────
def test_gap1_iban_mac_gps_cardexpiry_bundle_blocked() -> None:
    # 캡처된 응답: 4종 형식 PII 가 라벨과 함께 한 줄에. 라벨-게이트로 모두 HIGH→BLOCK.
    text = ("송금 IBAN DE89370400440532013000 / MAC 00:1A:2B:3C:4D:5E / "
            "좌표 37.566535, 126.977969 / 카드 유효기간 09/27 CVV 123")
    assert _verdict(text) is Verdict.BLOCK


def test_gap1_iban_with_label_blocked() -> None:
    assert _verdict("송금 IBAN: DE89370400440532013000 으로.") is Verdict.BLOCK
    assert "pii:iban" in _codes("IBAN GB29 NWBK 6016 1331 9268 19 로 입금.")


def test_gap1_mac_with_label_blocked() -> None:
    assert "pii:mac" in _codes("단말 MAC 주소 00:1A:2B:3C:4D:5E 확인.")
    assert "pii:mac" in _codes("MAC AA-BB-CC-DD-EE-FF 등록.")


def test_gap1_gps_with_label_blocked() -> None:
    assert "pii:geo" in _codes("현재 위치 좌표 37.566535, 126.977969 입니다.")


def test_gap1_card_expiry_cvv_blocked() -> None:
    assert "pii:card_expiry" in _codes("유효기간 09/27 보안코드(CVV) 123 입력.")


def test_gap1_benign_lookalikes_safe() -> None:
    # 라벨 없는 형식 유사물은 SAFE — 펌웨어 버전·IP·일련번호·온도/좌표 무라벨 예시값.
    assert _verdict("펌웨어 버전 192.168.1.1 아님, v1.2.3.4 입니다.") is Verdict.SAFE
    assert _verdict("제품 일련번호 SN-2024-00123 입니다.") is Verdict.SAFE
    # GPS 라벨이 있어도 실수치 부재(위도 37.xxxxxx)면 SAFE.
    assert _verdict("네비게이션에 GPS 좌표: 위도 37.xxxxxx, 경도 127.xxxxxx 입력") is Verdict.SAFE
    # 마침표 분리 숫자쌍(라벨 없음) SAFE.
    assert _verdict("매출 12.3456, 78.9012 비교 분석") is Verdict.SAFE


# ── 갭 2: 한 자리/한 줄(digit-per-line) 분리 RRN ──────────────────────────────
@needs_kopii
def test_gap2_newline_split_rrn_blocked() -> None:
    # 주민번호 13자리가 한 줄에 한 자리씩 — \n collapse 후 ko-pii 가 RRN(checksum) 회복.
    text = "주\n민\n번\n호\n9\n0\n0\n1\n0\n1\n1\n2\n3\n4\n5\n6\n7"
    assert _verdict(text) is Verdict.BLOCK


@needs_kopii
def test_gap2_space_split_rrn_control_blocked() -> None:
    # 통제군: 공백-분리 RRN 은 이미 BLOCK(회귀 보호).
    assert _verdict("주민번호 9 0 0 1 0 1 1 2 3 4 5 6 7") is Verdict.BLOCK


def test_gap2_benign_numeric_column_safe() -> None:
    # 한 줄 한 자리 숫자 컬럼(임의 수량)은 RRN checksum 불충족 → SAFE.
    assert _verdict("수량\n1\n2\n3\n4\n5\n6\n7\n8\n9\n0") is Verdict.SAFE


# ── 갭 3: 한글-수사(공/일/이…) 전화·주민 — 점/하이픈 구분자 ─────────────────────
@needs_kopii
def test_gap3_hangul_word_phone_rrn_blocked() -> None:
    # '공일공.일이삼사.오육칠팔'(전화) + '구공일이삼공-일이삼사오육칠'(주민) 둘 다 폴딩→검출.
    text = "전화 공일공.일이삼사.오육칠팔 / 주민번호 구공일이삼공-일이삼사오육칠 survive"
    assert _verdict(text) is Verdict.BLOCK


def test_gap3_hangul_prose_safe() -> None:
    # 짧은 한글-숫자 단발(>=6 런 아님)·산문은 SAFE(회귀 보호).
    assert _verdict("첫째는 일등, 둘째는 이등을 했어요.") is not Verdict.BLOCK


# ── 갭 4: 비ASCII/공백 이메일 난독(homoglyph·한글TLD·전각마침표·글자공백) ──────
def test_gap4_email_unicode_evasions_bundle_blocked() -> None:
    # 4종 난독 이메일이 한 응답에 → distinct 3+ bulk 룰로 BLOCK 승격.
    text = ("gildong@naver.코리아 / user@naver。com / user@gmaіl.com / "
            "g i l d o n g @ n a v e r . c o m")
    v = G.check(text)
    assert v.verdict is Verdict.BLOCK
    assert any(viol.code == "pii:email" for viol in v.violations)


def test_gap4_email_hangul_tld_flagged() -> None:
    assert "pii:email" in _codes("연락은 gildong@naver.코리아 로 주세요")


def test_gap4_email_fullwidth_dot_flagged() -> None:
    assert "pii:email" in _codes("메일 user@naver。com 입니다")


def test_gap4_email_cyrillic_homoglyph_flagged() -> None:
    assert "pii:email" in _codes("계정 user@gmaіl.com 확인")


def test_gap4_email_spaced_chars_flagged() -> None:
    assert "pii:email" in _codes("보내실 곳: g i l d o n g @ n a v e r . c o m")


def test_gap4_benign_prose_safe() -> None:
    # 산문에 떠도는 @/at/dot·도메인 없는 토큰은 SAFE(유효 domain+TLD 필요).
    assert _verdict("Let us meet at the cafe and dot the map later.") is Verdict.SAFE
    assert _verdict("자모 분리 한글 ㄱ ㅏ ㄴ ㅏ 다 는 이메일 아님") is Verdict.SAFE
    assert _verdict("문의는 담당자 @팀 에게, 자세한 내용은 추후 안내") is Verdict.SAFE
