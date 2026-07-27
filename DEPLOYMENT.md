# ko-output-guard Deployment

이 저장소는 `ko-output-guard` 패키지, 공개 정책 API와 제품 테스트의 canonical source다. 인증,
감사, 공통 정책 로더와 컨테이너 hardening을 포함한 HTTP 서비스 조립은
[`modak_experiments/deployment`](https://github.com/Marker-Inc-Korea/modak_experiments/tree/main/deployment)
에서 관리한다. 공용 런타임을 제품별로 복제하지 않기 위해 이 저장소에는 서비스 `Dockerfile`을 두지 않는다.

## Package Qualification

```bash
python -m pip install -e ".[dev,pii,normalize]"
python -m ruff check src tests
python -m mypy
python -m pytest
python -m build --sdist --wheel
```

릴리스 후보는 이 저장소의 clean commit에서 만들어야 하며, `ko-pii`와 `ko-prompt-guard`
통합 경로, wheel 검증과 Python 지원 버전 CI가 모두 통과해야 한다. 패키지 검증은 HTTP 서비스
승격을 대신하지 않는다.

## Service Contract

`POST /v1/check` 요청은 `{"text":"...", "context":"..."}` 형식이다. `context`는 선택 필드다.
BLOCK 응답은 원문이 아니라 안전하게 마스킹된 `safe_payload`만 제공한다. 감사 로그에는
request ID, 정책 digest, 판정, reason code, 지연과 원문 HMAC만 저장한다.

`GET /health/ready`는 최소 상태만 반환한다. 인증된 `/v1/metadata` 또는 `--check` preflight가
PII backend, 필수 detector, secret canary와 benign canary를 재현한다. `degraded=true`
결과를 정상 readiness로 승격하지 않는다.

배포 이미지는 고정된 `ko-pii`와 `ko-prompt-guard` revision을 포함하고, PII backend가 없으면
readiness를 실패시켜야 한다. 선택 ML/LLM reviewer는 Slurm GPU endpoint로 분리하고 별도 runtime
lock과 지연·FPR 증거를 제출해야 한다. 통합 저장소는 이미지에 이 저장소의 exact commit을 기록하고,
source digest, SBOM, signature와 preflight 결과를 함께 검증해야 한다. 식약처 하네스는 의료 benign
FPR, 위험 권고, PHI/API 누출과 배포 후 drift 증거를 별도로 요구한다.
