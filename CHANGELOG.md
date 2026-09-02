# Changelog

이 프로젝트의 사용자 영향 변경을 기록합니다.

## Unreleased

## 1.1.0 - 2026-09-02

### Added

- DLP, 콘텐츠 안전, 식약처 출력 통제를 분리해 선택할 수 있는 실제 `PolicyPack` preset을
  추가했습니다.
- JSON 응답과 tool-call 인자의 모든 문자열 값·키를 경로별로 검사하고 안전한 사본을 만드는
  `check_structured()`를 추가했습니다.
- 기본 구조화 telemetry는 입력 키를 노출하지 않고 finding 순번과 경로 깊이만 기록합니다.
- chunk 경계에서 나뉜 크리덴셜·PII를 선전송하지 않는 bounded `OutputStreamSession`과,
  원문을 기본 출력하지 않는 `ko-output-guard` CLI를 추가했습니다.

### Documentation

- 공개 단계를 `Development Preview`로 재분류하고 PyPI maturity를 Beta로 맞췄습니다.
  공개 소스와 운영 효과 보증을 구분하고 권장 용도를 평가·통합과 다층 방어로 한정했습니다.
- 출력 가드를 DLP, Content Safety, MFDS Safety policy pack으로 분리하고 pack별 보장 범위,
  Tier-2 필요 조건과 규제·임상 비보장 범위를 명확히 했습니다.

### Fixed

- 독립 CI가 현재 운영 계약보다 오래된 `ko-pii`, `ko-prompt-guard` revision을 검증하던
  문제를 수정했습니다.

## 1.0.0 - 2026-07-28

### Changed

- 모노레포의 `ko-output-guard/` 이력을 보존해 독립 저장소로 전환했습니다.
- 1.0 API 계약을 정하고 독립 CI와 통합 릴리스 증거에 연결했습니다.
- 독립 CI, 배포 경계, 보안 신고 및 기여 절차를 추가했습니다.
- 출력·context 자원 상한을 detector 전에 적용하고 oversized 원문을 결과에서 제거했습니다.
- `FLAG`, `BLOCK`, degraded 결과를 fail-closed 처리하는 `forward_safe`, `safe_text`,
  `enforce()` 계약과 원문 없는 telemetry DTO를 추가했습니다.

### Removed

- 통합 저장소가 담당해야 하는 중복 3축 평가 스크립트와 서비스 Dockerfile을 제거했습니다.

## 0.2.0

- 비밀·PII 누출, 범용 유해 콘텐츠, 식약처 도메인 위험 권고, 독성, 자해, 무기 및
  prompt leak 검사를 포함합니다.
- 이 버전은 독립 저장소의 첫 릴리스 후보이며 stable tag는 별도 승격 gate 통과 후 생성합니다.
