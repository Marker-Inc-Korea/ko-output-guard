"""적대적 입력 회귀 테스트 — secret.py.

각 gap 은 캡처된 응답 텍스트 → 기대 verdict 로 고정한다. 모두 LIVE Guard().check()
경로로 검증한다(결정론 detector 만 사용, 네트워크 없음).

R4 세 gap (모두 이전엔 SAFE/FLAG → 누락):
  1. Stripe webhook signing secret(whsec_…) — stripe_key 대안에 추가.
  2. Twilio Account SID(AC + 32 hex) + bare 32-hex auth token — 신규 twilio_account_sid.
  3. conn-string 비번에 '@' 포함(P@ssw0rdLong) — 첫 '@'에서 끊겨 매칭 실패하던 것을
     마지막 @host 앵커 대안을 ADD 해 복원.

동반 benign look-alike(@-free/redis/mysql conn, AC prose, lowercase ac, git/MD5 hex,
placeholder)는 recall-safe 보장을 위해 non-BLOCK 으로 유지돼야 한다.
"""
from __future__ import annotations

import pytest

from ko_output_guard import Guard
from ko_output_guard.result import Verdict

GUARD = Guard()


# --- FIXABLE gaps: one per captured reply -> expected verdict ------------------
@pytest.mark.parametrize(
    "reply, expected",
    [
        # gap 1: Stripe whsec_ webhook secret (이전엔 generic_secret FLAG 에 그침)
        (
            "const endpointSecret = 'whsec_REDACTED_TEST';",
            Verdict.BLOCK,
        ),
        # gap 2: Twilio AC SID(AC+32hex) + bare 32-hex auth token (이전엔 SAFE)
        (
            "twilio account AC_REDACTED_TEST_SID "
            "with token a1b2c3d4e5f67890a1b2c3d4e5f67890",
            Verdict.BLOCK,
        ),
        # gap 3: conn-string 비번에 '@' 포함 (이전엔 첫 '@'에서 끊겨 SAFE)
        (
            "postgresql://app:P@ssw0rdLong@db.internal:5432/fda",
            Verdict.BLOCK,
        ),
        # 캡처된 합본 응답(세 신호 동시) — BLOCK 유지
        (
            "const endpointSecret = 'whsec_REDACTED_TEST'; / "
            "twilio,AC_REDACTED_TEST_SID,"
            "a1b2c3d4e5f67890a1b2c3d4e5f67890 / "
            "postgresql://app:P@ssw0rdLong@db.internal:5432/fda",
            Verdict.BLOCK,
        ),
    ],
)
def test_r4_secret_gaps_block(reply: str, expected: Verdict) -> None:
    result = GUARD.check(reply)
    assert result.verdict is expected, (
        f"{reply!r} -> {result.verdict} (expected {expected}); "
        f"violations={[v.code for v in result.violations]}"
    )


# --- control: conn-string with @-free password still BLOCKs (no regression) ----
def test_r4_conn_string_at_free_still_blocks() -> None:
    reply = "postgresql://app:SimplePass123@db.internal:5432/fda"
    result = GUARD.check(reply)
    assert result.verdict is Verdict.BLOCK, (
        f"{reply!r} -> {result.verdict}; "
        f"violations={[v.code for v in result.violations]}"
    )


# --- recall-safe: benign look-alikes must NOT block ----------------------------
@pytest.mark.parametrize(
    "reply",
    [
        # @-free / no-password / scheme-only conn strings → 비번 캡처 없음
        "redis://localhost:6379/0",
        "Use the redis://cache:6379 endpoint.",
        "mysql://localhost:3306/mydb has no password.",
        "mongodb://localhost/test database connection",
        # conn-string with placeholder password → _PLACEHOLDER 필터
        "postgresql://app:<your_password_here>@db.internal:5432/fda",
        # Twilio AC look-alikes: 짧은/소문자/접두만 → SID 형식 불일치
        "function AC123 does nothing.",
        "ACID transactions in postgres are durable.",
        "transaction ac1234567890abcdef1234567890abcdef in lowercase",
        "Account AC1234567890abcdef1234567890abcde only 31 hex.",
        # bare 32-hex without AC SID context → git/MD5 등은 SAFE 유지
        "git commit a3f9c2e8b1d4f6a9c3e7b2d5f8a1c4e7 was reverted.",
        "The MD5 checksum is a3f9c2e8b1d4f6a9c3e7b2d5f8a1c4e7 for the file.",
    ],
)
def test_r4_benign_lookalikes_not_blocked(reply: str) -> None:
    result = GUARD.check(reply)
    assert result.verdict is not Verdict.BLOCK, (
        f"{reply!r} unexpectedly BLOCK; "
        f"violations={[(v.code, v.severity.name) for v in result.violations]}"
    )
