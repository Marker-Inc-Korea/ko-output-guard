# ko-output-guard Deployment

`ko-output-guard`는 현재 **Development Preview**다. 아래 계약은 평가 환경과 배포 후보에서
재현 가능하게 검증하기 위한 기준이며, 고객 환경의 pack별 효과나 단독 운영 적합성을 보증하지 않는다.

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
서비스는 `GuardPolicy.max_text_chars`와 `max_context_chars`를 요청 경계에 설정해야 하며, 상한 초과는
detector 실행 없이 `RESOURCE_LIMIT` BLOCK으로 처리한다. 응답의 `safe_payload`는 verdict와 무관하게
`GuardResult.safe_text`만 사용한다. 따라서 FLAG/degraded 결과도 원문을 재방출하지 않는다. 직접 전달은
`GuardResult.forward_safe`가 참인 결과만 허용하거나 `enforce()`를 사용하며, 후자는 FLAG/BLOCK/degraded에
`GuardBlocked`를 발생시킨다. 감사 로그에는 `to_safe_telemetry()`의 code/category/severity와 request ID,
정책 digest, 지연, 원문 HMAC만 저장하고 원문, matched substring, detector reason은 저장하지 않는다.

`GET /health/ready`는 최소 상태만 반환한다. 인증된 `/v1/metadata` 또는 `--check` preflight가
PII backend, 필수 detector, secret canary와 benign canary를 재현한다. `degraded=true`
결과를 정상 readiness로 승격하지 않는다.

배포 이미지는 고정된 `ko-pii`와 `ko-prompt-guard` revision을 포함하고, PII backend가 없으면
readiness를 실패시켜야 한다. 선택 ML/LLM reviewer는 Slurm GPU endpoint로 분리하고 별도 runtime
lock과 지연·FPR 증거를 제출해야 한다. 통합 저장소는 이미지에 이 저장소의 exact commit을 기록하고,
source digest, SBOM, signature와 preflight 결과를 함께 검증해야 한다. 식약처 하네스는 의료 benign
FPR, 위험 권고, PHI/API 누출과 배포 후 drift 증거를 별도로 요구한다.
