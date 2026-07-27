# Contributing

## Before You Start

동작 변경은 먼저 issue에서 위협 모델, 예상 판정과 한국어 과탐 영향을 합의해 주십시오. 보안 문제는
공개 issue 대신 [SECURITY.md](./SECURITY.md)의 비공개 절차를 사용합니다.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,pii,normalize]"
python -m ruff check src tests
python -m mypy
python -m pytest
```

새 탐지 규칙에는 유해 예시와 어휘가 겹치는 정상 출력, masking 결과를 함께 고정해야 합니다.
optional backend 부재를 조용히 안전 판정으로 바꾸지 말고 degraded/fail-closed 계약을 유지하십시오.

## Pull Requests

- 한 PR은 하나의 명확한 동작 변경에 집중합니다.
- 사용자 영향 변경은 `CHANGELOG.md`의 `Unreleased`에 기록합니다.
- 새 category, severity 또는 masking 계약은 README와 공개 API 문서를 함께 갱신합니다.
- 실제 개인정보, 환자 정보, 고객 출력, 자격증명과 비공개 평가 데이터는 커밋하지 않습니다.
- CI의 지원 Python 버전 테스트, ruff, mypy, pytest와 distribution build를 모두 통과합니다.
