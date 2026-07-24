# ko-output-guard Deployment

배포 이미지는 출력 누출·유해 콘텐츠를 검사하는 결정론 서비스다. PII 검출 backend가 없으면
readiness가 실패하도록 `strict` 모드로 고정한다. 이미지에는 고정된 `ko-pii` source commit과
`ko-prompt-guard` 정규화기가 포함된다.

선택 ML/LLM reviewer 환경변수(`KO_OUT_CLF_DIR`, `KO_HARMFUL_CLF_DIR`, `KO_JUDGE_URL`)가 서비스에
직접 설정되면 readiness가 실패한다. 모델 reviewer는 Slurm GPU endpoint로 분리하고 별도 runtime
lock과 지연·FPR 증거를 제출해야 한다.

## Build

```bash
docker build -f ko-output-guard/Dockerfile \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t ko-output-guard:0.2.0rc1 .
```

## Run

```bash
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8082:8080 \
  -e KO_GUARD_API_TOKEN="$KO_GUARD_API_TOKEN" \
  -e KO_GUARD_AUDIT_HMAC_KEY="$KO_GUARD_AUDIT_HMAC_KEY" \
  -v "$PWD/deployment/policies/output-production.json:/run/policy.json:ro" \
  -e KO_GUARD_POLICY_FILE=/run/policy.json \
  ko-output-guard:0.2.0rc1
```

두 secret은 서로 다른 최소 32바이트 값이어야 하며 외부 bind에서는 모두 필수다.

## API

`POST /v1/check` 요청은 `{"text":"...", "context":"..."}` 형식이다. `context`는 선택 필드다.
BLOCK 응답은 원문이 아니라 안전하게 마스킹된 `safe_payload`만 제공한다. 감사 로그에는
request ID, 정책 digest, 판정, reason code, 지연과 원문 HMAC만 저장한다.

`GET /health/ready`는 최소 상태만 반환한다. 인증된 `/v1/metadata` 또는 `--check` preflight가
PII backend, 필수 detector, secret canary와 benign canary를 재현한다. `degraded=true`
결과를 정상 readiness로 승격하지 않는다.

배포 승격은 [suite deployment contract](../deployment/README.md)를 따른다. 식약처 하네스는
의료 benign FPR, 위험 권고, PHI/API 누출과 배포 후 drift 증거를 별도로 요구한다.
