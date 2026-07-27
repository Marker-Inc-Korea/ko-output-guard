# Security Policy

## Supported Versions

보안 수정은 `main`과 최신 태그에 우선 적용합니다. 현재 `0.2.0`은 Beta 릴리스 후보이며,
stable 지원을 주장하지 않습니다.

## Reporting

출력 필터 우회, fail-open, PII/secret 노출, 안전하지 않은 masking 또는 공급망 문제는 공개
issue로 먼저 보고하지 마십시오. 저장소의 **Security > Report a vulnerability**를 사용해
재현 절차, 영향 범위, 영향을 받는 commit과 가능한 완화책을 비공개로 전달해 주십시오.

private vulnerability reporting을 사용할 수 없다면 공개 exploit이나 실제 데이터 없이
최소한의 연락 요청만 issue에 남기고, 저장소 관리자가 비공개 채널을 제공할 때까지 상세 내용을
게시하지 마십시오.

관리자는 영업일 기준 3일 이내 접수를 확인하고, 7일 이내 초기 영향 판정과 다음 일정을
공유하는 것을 목표로 합니다.

## Scope

- PII, secret, harmful-content 또는 prompt-leak 탐지 우회
- 차단 응답이나 감사 정보에서 원문이 재노출되는 문제
- optional backend 부재가 안전한 상태로 오인되는 fail-open
- 패키지, CI 또는 릴리스 provenance 위조

실제 개인정보, 자격증명, 환자 정보, 고객 출력 또는 미공개 공격 payload를 공개 저장소에
올리지 마십시오.
