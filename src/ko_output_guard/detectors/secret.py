"""크리덴셜/시크릿 누출 탐지 — LLM 이 출력에 API key·토큰·private key 를 뱉는 경우.

알려진 고-엔트로피 토큰 형식(gitleaks/detect-secrets 계열)을 정규식으로 잡는다.
형식이 확정적인 클라우드/서비스 키는 CRITICAL, 범용 'key=...' 할당은 오탐 여지가
있어 MEDIUM. 모두 원본 텍스트 대상(normalize 불필요 — 토큰은 ASCII).
"""
from __future__ import annotations

import re

from ..result import Category, Severity, Violation

# (code, compiled, severity)
_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    # AKIA(장기 키) + ASIA(STS 임시 키) 모두.
    ("aws_access_key", re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("aws_secret", re.compile(r"(?i)aws.{0,20}?(?:secret|key).{0,5}['\"=:\s]([A-Za-z0-9/+]{40})\b"),
     Severity.CRITICAL),
    ("github_pat", re.compile(r"\bgh[pos]_[0-9A-Za-z]{36}\b"), Severity.CRITICAL),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{59,}\b"), Severity.CRITICAL),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), Severity.CRITICAL),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), Severity.CRITICAL),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.CRITICAL),
    ("slack_token", re.compile(r"\bxox[baprse]-[0-9A-Za-z-]{10,}\b"), Severity.CRITICAL),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{24,}\b"), Severity.CRITICAL),
    ("private_key_block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA |ENCRYPTED )?PRIVATE KEY-----",
                re.IGNORECASE),
     Severity.CRITICAL),
    # JWT — 3세그먼트가 정석이나 signature 누락(2세그) + 줄바꿈 wrapping(\s* 허용)도 잡는다.
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\s*\.\s*eyJ[A-Za-z0-9_-]{8,}"
                r"(?:\s*\.\s*[A-Za-z0-9_-]{8,})?"),
     Severity.HIGH),
    ("bearer_token", re.compile(r"\bBearer\s+([A-Za-z0-9_\-.=]{20,})", re.IGNORECASE),
     Severity.HIGH),
    # 범용 'api_key = "..."' 류 — 오탐 여지(설명용 placeholder)라 MEDIUM.
    # 보강: var-keyword 를 확장 — 단어 경계 단일 키워드 외에 *접미사형* 식별자
    # (BARE *_KEY/_TOKEN/_SECRET, 예: ALGOLIA_ADMIN_KEY) 와 X-Auth-Key 헤더도 포함한다.
    # 접미사형은 식별자 1+ 글자 뒤 _key/_token/_secret 로 끝나야 하므로(=구분자 필수)
    # 'monkey'/'broken' 같은 prose 단어는 매칭되지 않는다. 모두 [:=] 할당 필수 →
    # git/MD5 같은 *프로즈* hex 는 var=value 형태가 아니라 영향 없음.
    ("generic_secret_assignment",
     re.compile(
         r"(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key"
         r"|x-auth-key|\b[a-z][a-z0-9]*(?:_[a-z0-9]+)*_(?:key|token|secret))"
         r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"
     ),
     Severity.MEDIUM),
    # --- 연결 문자열 / 추가 서비스 토큰 형식(red-team 발견) ---
    # scheme://user:PASSWORD@host — postgres/mysql/mongodb/redis/amqp 등. group(1)=password.
    ("db_connection_string",
     re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]*:([^/\s:@]{6,})@"), Severity.HIGH),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), Severity.CRITICAL),
    ("azure_storage_key",
     re.compile(r"AccountKey=([A-Za-z0-9+/]{40,}={0,2})"), Severity.CRITICAL),
    ("azure_ad_secret", re.compile(r"\b[A-Za-z0-9~._-]{2,4}~[A-Za-z0-9~._-]{30,}\b"), Severity.HIGH),
    ("sendgrid_key",
     re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), Severity.CRITICAL),
    ("discord_token",
     re.compile(r"\b[MNO][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b"),
     Severity.HIGH),
    ("slack_webhook",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"), Severity.HIGH),
    # prefix 가 고유한 서비스 토큰 형식(gitleaks/detect-secrets 계열) — 저-FP.
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), Severity.HIGH),
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), Severity.HIGH),
    ("digitalocean_pat", re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), Severity.HIGH),
    ("shopify_token", re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"), Severity.HIGH),
    ("pypi_token", re.compile(r"\bpypi-AgEI[A-Za-z0-9_-]{50,}"), Severity.CRITICAL),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33,}\b"), Severity.HIGH),
    ("mailgun_key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), Severity.HIGH),
    ("square_token", re.compile(r"\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}\b"), Severity.HIGH),
    # JDBC/쿼리형 비밀번호(scheme://user:pass@ 의 sibling) — group(1)=password.
    ("jdbc_password",
     re.compile(r"(?i)jdbc:[^\s]*[?;&]password=([^\s&;]{6,})"), Severity.HIGH),
    # base64 로 감싼 키 누출 유도 — '디코드하면 키/토큰' 프레이밍 + 실제 base64 blob 필수.
    ("base64_wrapped_secret",
     re.compile(r"(?i)base64[^.\n]{0,18}?(?:디코드|디코딩|decode)[^.\n]{0,18}?"
                r"(?:키|토큰|비밀|시크릿|secret|key|password)[^.\n]{0,20}?[A-Za-z0-9+/]{24,}={0,2}"),
     Severity.MEDIUM),
    # '키/토큰: <blob>' 라벨링 — 약한 신호라 scan 에서 char-class 다양성+예시맥락 필터.
    ("labeled_secret_blob",
     re.compile(r"(?:키|토큰|비밀번호|시크릿)\s*:?\s*([A-Za-z0-9+/]{20,}={0,2})"),
     Severity.MEDIUM),
    # Google/GCP OAuth — prefix 고유(gitleaks 계열).
    ("google_oauth_access", re.compile(r"\bya29\.[A-Za-z0-9_\-]{20,}"), Severity.CRITICAL),
    ("google_oauth_refresh", re.compile(r"\b1//0[A-Za-z0-9_\-]{30,}"), Severity.CRITICAL),
    # Docker config.json auth — base64(user:password). group(1)=blob.
    ("docker_config_auth",
     re.compile(r'(?i)"auth"\s*:\s*"([A-Za-z0-9+/]{20,}={0,2})"'), Severity.HIGH),
    # 강한 라벨(encryption/private/credential/master/signing + key/secret) + 긴 hex.
    ("labeled_hex_secret",
     re.compile(r"(?i)(?:encryption|private|credential|master|signing)[_\s]?"
                r"(?:key|secret|token)[_\s:=]{1,3}([a-f0-9]{32,64})\b"), Severity.HIGH),
    # 보강: 강한 KO/EN 시크릿 라벨(비밀번호|시크릿|secret|password) + 연속 all-hex(32~64).
    # all-hex 는 labeled_secret_blob 의 대/소/숫자 혼합 요건을 통과 못 해 누락됐다. 강한
    # 라벨이 명시적으로 붙어야만 HIGH 로 잡으므로 git-hash/MD5(라벨 없음·'해시:' 등 약한
    # 라벨)는 그대로 SAFE. 라벨과 값 사이는 콜론/등호/공백만 허용(짧은 윈도, 백트래킹 없음).
    ("labeled_hex_blob",
     re.compile(r"(?i)(?:비밀번호|시크릿|\bsecret|\bpassword)\s*[:=]?\s*([a-f0-9]{32,64})\b"),
     Severity.HIGH),
]

# 명백한 placeholder/예시는 generic 오탐에서 제외. .match()(prefix-anchored)는
# 'test'로 *시작하는* 진짜 고-엔트로피 키('test1234abcdEFGH5678realkey')까지 placeholder로
# 떨궈 누출을 놓친다. 그래서 .fullmatch() 로 *값 전체*가 placeholder 일 때만 제외한다.
# 단일 토큰뿐 아니라 placeholder 단어들이 구분자로 이어진 *구절*('REPLACE_WITH_YOUR_TOKEN',
# 'YOUR_ACCESS_TOKEN_HERE', 'your_password')도 통째로 placeholder 면 제외(과탐 방지).
_PLACEHOLDER_WORD = (
    r"your|the|example|placeholder|xxx+|insert|todo|changeme|abc123|test|dummy|sample|"
    r"redacted|password|passwd|replace|change_?me|documentation|with|here|value|access|"
    r"my|key|token|secret|pass|none|null|fake|temp|0+|1+|\*+"
)
_PLACEHOLDER = re.compile(
    rf"(?i)(?:<.*>|\.\.\.|(?:{_PLACEHOLDER_WORD})(?:[_\-]?(?:{_PLACEHOLDER_WORD}))*[0-9]*)",
)
# 값에 'example'이 substring 으로 박혀 있다고 무조건 예시로 보면 진짜 키에 'example'
# 만 덧대 우회된다('exampleAKIA…REALKEY'). 그래서 *값 전체*가 예시·placeholder 성분으로만
# 구성될 때만(fullmatch) 예시로 간주한다.
_EXAMPLE_VAL = re.compile(
    r"(?i)(?:example|sample|dummy|placeholder|documentation|redacted|your|the|test|"
    r"value|here|none|null|fake|xxx+|[_\-0-9])+")
# '키/토큰: <blob>' 주변에 예시·형식·시그니처 언급이면 실제 누출 아님.
_EXAMPLE_CTX = re.compile(
    r"(?i)예시|샘플|sample|example|형식|포맷|format|시그니처|signature|시작하는|로\s*시작"
)
# 값(group 1)이 placeholder/예시면 건너뛰는 패턴들.
_VALUE_GUARDED = frozenset({
    "generic_secret_assignment", "db_connection_string", "azure_storage_key",
    "jdbc_password", "bearer_token", "labeled_secret_blob",
    "docker_config_auth", "labeled_hex_secret", "labeled_hex_blob",
})

# 공백 한 칸/제로폭 한 글자만 끼면 raw 텍스트의 모든 credential 패턴이 깨진다
# ('AKIA IOSFODNN7EXAMPLE'). 그래서 공백·제로폭을 걷어낸 *사본*에서도 재스캔하고 원본
# offset 으로 역매핑한다(pii_leak.py 의 collapse+remap 접근 재사용). prose 의 단어 사이
# 공백을 지우면 임의 영숫자 덩어리가 생겨 약한 패턴(generic/labeled blob)은 오탐하므로,
# 사본 재스캔은 *prefix 가 고유한 강한 형식 토큰*에만 적용한다(저-FP).
_COLLAPSE_CHARS = frozenset(
    " \t\r\n​‌‍⁠﻿ ")  # 공백·탭·개행·제로폭·BOM·NBSP
# 사본(공백 제거) 재스캔에 쓸 강한 패턴 코드 — prefix 고유라 prose 오탐이 사실상 없다.
_COLLAPSE_SAFE_CODES = frozenset({
    "aws_access_key", "github_pat", "github_fine_grained", "openai_key",
    "anthropic_key", "google_api_key", "slack_token", "stripe_key", "npm_token",
    "sendgrid_key", "discord_token", "huggingface_token", "gitlab_pat",
    "digitalocean_pat", "shopify_token", "pypi_token", "telegram_bot_token",
    "square_token", "google_oauth_access", "google_oauth_refresh", "private_key_block",
})
# 사본 전용 완화 패턴 — 공백/제로폭으로 쪼개진 짧은 OpenAI/Anthropic 키('sk-proj-aB3dEf
# GhIjKlMn')는 합쳐도 길이 floor({20,})에 못 미쳐 raw 패턴이 놓친다. prefix('sk-proj-'/
# 'sk-ant-')가 극히 고유하므로 사본에서만 10자+ 꼬리로 잡는다(raw prose FP 없음).
_COLLAPSE_EXTRA_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("openai_key", re.compile(r"\bsk-(?:proj-|ant-)[A-Za-z0-9_-]{10,}\b"), Severity.CRITICAL),
]


def scan_secrets(text: str) -> list[Violation]:
    out = _scan_secrets_impl(text)
    # 공백/제로폭을 걷어낸 사본에서 강한 형식 토큰만 재스캔(우회 복원).
    collapsed_chars: list[str] = []
    idx_map: list[int] = []
    for i, ch in enumerate(text):
        if ch not in _COLLAPSE_CHARS:
            collapsed_chars.append(ch)
            idx_map.append(i)
    collapsed = "".join(collapsed_chars)
    if collapsed != text:
        covered = [(v.start, v.end) for v in out
                   if v.start is not None and v.end is not None]
        for v in _scan_secrets_impl(collapsed, only=_COLLAPSE_SAFE_CODES,
                                    extra=_COLLAPSE_EXTRA_PATTERNS):
            if v.start is None or v.end is None:
                continue
            s = idx_map[v.start]
            e = idx_map[v.end - 1] + 1
            # 원본에서 이미 같은 구간을 잡았으면 중복 제거(우회 안 된 정상 매칭).
            if any(os_ <= s and e <= oe for os_, oe in covered):
                continue
            out.append(v.model_copy(update={"start": s, "end": e}))
    return out


def _scan_secrets_impl(
    text: str,
    only: frozenset[str] | None = None,
    extra: list[tuple[str, re.Pattern[str], Severity]] | None = None,
) -> list[Violation]:
    out: list[Violation] = []
    seen: set[tuple[int, int]] = set()
    patterns = _PATTERNS if extra is None else [*_PATTERNS, *extra]
    for code, pat, sev in patterns:
        if only is not None and code not in only:
            continue  # 사본 재스캔은 강한 형식 토큰만(저-FP)
        for m in pat.finditer(text):
            span = (m.start(), m.end())
            if span in seen:
                continue
            # 캡처 그룹(값)이 있는 패턴은 placeholder/예시 값이면 건너뜀(과탐 방지).
            if code in _VALUE_GUARDED and m.groups():
                val = m.group(1)
                # fullmatch — 값 *전체*가 placeholder 일 때만 제외(prefix 우회 차단).
                if _PLACEHOLDER.fullmatch(val) or len(set(val)) <= 3:
                    continue
                if code in ("generic_secret_assignment", "labeled_secret_blob") \
                        and _EXAMPLE_VAL.fullmatch(val):
                    continue
            # 라벨링 blob 은 약한 신호 — base64 시크릿은 대/소/숫자 혼합. 단일 char-class
            # (hex·소문자 단어·대문자+숫자 식별자)와 예시·형식 맥락은 실제 누출 아님.
            if code == "labeled_secret_blob":
                val = m.group(1)
                if not (re.search(r"[A-Z]", val) and re.search(r"[a-z]", val)
                        and re.search(r"[0-9]", val)):
                    continue
                if _EXAMPLE_CTX.search(text[max(0, m.start() - 16):m.end() + 16]):
                    continue
            # 광범위 매칭 패턴(틸드 포함 Azure AD)은 저-엔트로피(반복/placeholder)면 건너뜀.
            if code == "azure_ad_secret" and len(set(m.group(0))) <= 6:
                continue
            # PEM 헤더 단독('…형식이라고 설명')은 예시 — 헤더와 본문 사이 공백/주석이
            # 200자를 넘으면 본문을 못 봐 누출이 묵살된다. 헤더 자체를 신호로 보되, 본문이
            # 있으면(공백 무관) 확정. 헤더만 있고 본문이 전무하면 예시로 본다.
            if code == "private_key_block":
                tail = text[m.end():]
                if "PRIVATE KEY" not in m.group(0).upper():
                    pass  # 방어적(정상 매칭이면 헤더는 항상 포함)
                # 헤더 뒤 어디든 base64 본문이 있으면 확정 누출(윈도 제한 제거).
                has_body = bool(re.search(r"[A-Za-z0-9+/]{40,}", tail)
                                or re.search(r"-----END", tail, re.IGNORECASE))
                if not has_body and _EXAMPLE_CTX.search(
                        text[max(0, m.start() - 24):m.end() + 24]):
                    continue  # 본문 없음 + 예시/형식 맥락 → 설명용 예시
            # placeholder/예시 필터를 통과한 generic 값이 고-엔트로피(대/소/숫자 혼합,
            # 20자+)면 진짜 누출이므로 MEDIUM→HIGH 로 올려 BLOCK 한다. 사전형/짧은 값은 FLAG.
            eff_sev = sev
            if code == "generic_secret_assignment" and m.groups():
                val = m.group(1)
                # 진짜 키면 MEDIUM→HIGH 승격해 BLOCK. 두 신호:
                # (a) 고-엔트로피 혼합(대/소/숫자 20자+, 고유문자 10+)
                # (b) 보강: var/라벨 하 32자+ 연속 all-hex(대/소문자 무관, 고유 hex 6+).
                #     git-hash/MD5 는 var=value 형태가 아니라 여기 도달하지 않는다.
                mixed = (len(val) >= 20 and re.search(r"[a-z]", val)
                         and re.search(r"[A-Z]", val) and re.search(r"[0-9]", val)
                         and len(set(val)) >= 10)
                all_hex = (re.fullmatch(r"[a-fA-F0-9]{32,64}", val) is not None
                           and len(set(val.lower())) >= 6)
                if mixed or all_hex:
                    eff_sev = Severity.HIGH
            seen.add(span)
            out.append(
                Violation(
                    code=code,
                    category=Category.SECRET_LEAK,
                    severity=eff_sev,
                    reason=f"credential/secret in output: {code}",
                    start=m.start(),
                    end=m.end(),
                    matched=m.group(0)[:60],
                )
            )
    return out
