"""PII false-positive 도메인 필터 회귀 — 비식별 속성/구조화-데이터/공개 식별자는 누출 아님,
결정적 식별 PII(RRN/카드/전화/이메일/사업자/여권)는 그대로 탐지.

실 식약처 코퍼스(qtaoa 출력 + drug_permit RAG 청크 + 비정형 산문)에서 pii_leak FP ~5,000건
(IP=의약품코드/버전번호, WEIGHT/HEIGHT=임상수치, POSTAL_CODE=표 코드, DT_BIRTH=허가/시험일,
NATIONALITY/URL/EDUCATION/POSITION=비식별 속성/공개, 15XX/16XX 대표번호=공개 고객센터)를
ko-pii 무수정 + 가드측 _EXCLUDE/대표번호 필터로 억제. ko-pii 위임이라 PERSON/ADDRESS 는 이미 비탐.
"""
from __future__ import annotations

import pytest

from ko_output_guard import Category, Guard

G = Guard()


def _has_pii(t: str) -> bool:
    return Category.PII_LEAK in {v.category for v in G.check(t).violations}


# --- 비식별/구조화/공개 → PII 누출 아님(SAFE) ---------------------------------------
PII_BENIGN = [
    "서버 버전은 2.113.111.4 입니다",                 # IP = 버전번호
    "이 약품 코드는 1.06.010.4 입니다",                # IP = 코드
    "성인 기준 체중 60 kg, 신장 1.73 m 환자",          # WEIGHT/HEIGHT 임상수치
    "우편 구분 코드 25-100, 300-250 참조",             # POSTAL_CODE = 표 코드
    "국적: 한국, 제조국: 대한민국",                     # NATIONALITY 속성
    "자세한 내용은 https://nedrug.mfds.go.kr 에서 확인", # URL 공개
    "연세대학교 약학과 졸업, 직책은 약사입니다",          # EDUCATION/POSITION 속성
    "품목 허가일 2024-04-23, 제조일 2023-09-28",        # DT_BIRTH = 허가/제조일
    "고객 문의는 1661-2000 으로 연락 주세요",            # 대표번호(15XX/16XX) 공개
    "상담 전화 1588-1234 운영 중입니다",                # 대표번호
]


@pytest.mark.parametrize("t", PII_BENIGN, ids=lambda s: s[:24])
def test_pii_domain_no_false_positive(t: str) -> None:
    assert not _has_pii(t), t


# --- 결정적 식별 PII → 그대로 탐지(과교정 방지) -------------------------------------
PII_REAL = [
    "문의는 safety@daewonpharm.co.kr 으로 연락 주세요",   # EMAIL
    "담당자 휴대폰 010-1234-5678",                       # PHONE (실 모바일)
    "유선 02-123-4567 로 문의",                          # PHONE (실 유선)
    "카드번호 5424-6123-2591-3555 로 결제",               # CARD
    "주민등록번호 뒷자리는 1234567 입니다",                # partial RRN
]


@pytest.mark.parametrize("t", PII_REAL, ids=lambda s: s[:24])
def test_pii_real_still_detected(t: str) -> None:
    assert _has_pii(t), t
