"""Bounded pre-forward session for chunked model output."""
from __future__ import annotations

from dataclasses import dataclass

from .guard import Guard
from .result import GuardResult


class OutputStreamClosed(RuntimeError):
    """Raised when a closed output stream is reused."""


class OutputStreamLimitExceeded(ValueError):
    """Raised after an output stream exceeds its configured budget."""


@dataclass(frozen=True)
class OutputStreamStatus:
    buffered_chars: int
    max_chars: int
    closed: bool
    failed: bool


class OutputStreamSession:
    """Inspect a complete bounded response before returning forwardable text."""

    def __init__(
        self,
        guard: Guard | None = None,
        *,
        context: str | None = None,
        max_chars: int | None = None,
    ) -> None:
        self.guard = guard or Guard()
        configured = self.guard.policy.max_text_chars if max_chars is None else max_chars
        if not isinstance(configured, int) or isinstance(configured, bool) or configured < 1:
            raise ValueError("max_chars must be a positive integer")
        if configured > self.guard.policy.max_text_chars:
            raise ValueError("max_chars cannot exceed GuardPolicy.max_text_chars")
        if context is not None and not isinstance(context, str):
            raise TypeError("context must be str or None")
        self.context = context
        self.max_chars = configured
        self._chunks: list[str] = []
        self._chars = 0
        self._closed = False
        self._failed = False

    @property
    def status(self) -> OutputStreamStatus:
        return OutputStreamStatus(self._chars, self.max_chars, self._closed, self._failed)

    def feed(self, chunk: str) -> OutputStreamStatus:
        self._ensure_open()
        if not isinstance(chunk, str):
            raise TypeError(f"feed() expects str, got {type(chunk).__name__}")
        if self._chars + len(chunk) > self.max_chars:
            self._chunks.clear()
            self._chars = 0
            self._closed = True
            self._failed = True
            raise OutputStreamLimitExceeded(
                f"output stream exceeds max_chars={self.max_chars}; no content was released"
            )
        self._chunks.append(chunk)
        self._chars += len(chunk)
        return self.status

    def finalize(self) -> GuardResult:
        self._ensure_open()
        source = "".join(self._chunks)
        self._chunks.clear()
        self._chars = 0
        self._closed = True
        try:
            return self.guard.check(source, self.context)
        except Exception:
            self._failed = True
            raise

    def abort(self) -> OutputStreamStatus:
        self._ensure_open()
        self._chunks.clear()
        self._chars = 0
        self._closed = True
        return self.status

    def _ensure_open(self) -> None:
        if self._closed:
            raise OutputStreamClosed("output stream is already closed")


__all__ = [
    "OutputStreamClosed",
    "OutputStreamLimitExceeded",
    "OutputStreamSession",
    "OutputStreamStatus",
]
