import pytest

from ko_output_guard import (
    Guard,
    GuardPolicy,
    OutputStreamClosed,
    OutputStreamLimitExceeded,
    OutputStreamSession,
    Verdict,
)


def test_cross_chunk_secret_is_blocked_before_release() -> None:
    stream = OutputStreamSession(Guard(GuardPolicy.dlp(detect_pii=False)))
    stream.feed("운영 키: sk-proj-")
    stream.feed("aB3dEfGhIjKlMnOpQrStUvWx")
    result = stream.finalize()
    assert result.verdict is Verdict.BLOCK
    assert "sk-proj" not in result.safe_text


def test_limit_failure_discards_and_closes() -> None:
    policy = GuardPolicy.content_safety(max_text_chars=8)
    stream = OutputStreamSession(Guard(policy), max_chars=5)
    stream.feed("1234")
    with pytest.raises(OutputStreamLimitExceeded, match="no content was released"):
        stream.feed("56")
    assert stream.status.buffered_chars == 0
    assert stream.status.failed is True
    with pytest.raises(OutputStreamClosed):
        stream.finalize()
