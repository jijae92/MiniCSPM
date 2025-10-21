# 통제 매핑 표

| Check ID | CIS 조항 | 통제 제목 | 권장 Remediation | 서비스 | 위험도 |
|----------|----------|-----------|-------------------|---------|---------|
| CIS-1.1 | 1.1 | Root account MFA enabled | 루트 계정에 가상/하드웨어 MFA 적용 | IAM | **높음** – 루트 자격 증명 탈취 위험 |
| CIS-1.2 | 1.2 | No root access keys | 루트 액세스 키 제거 및 필요 시 일회성 재발급 | IAM | **높음** – 키 유출 시 전체 계정 탈취 |
| CIS-1.5 | 1.5 | Strong password policy | 최소 14자, 대/소문자·숫자·기호 요구, 재사용 제한 24회, 만료 90일 | IAM | **보통** – 계정 탈취 가능성 증가 |
| CIS-1.22 | 1.22 | MFA for console users | 콘솔 사용자 전원에게 MFA 등록 강제 | IAM | **높음** – 피싱 후 세션 하이재킹 |
| CIS-2.1 | 2.1 | Multi-region CloudTrail | 조직/계정 Trail을 다중 리전으로 설정하고 로깅 상태 확인 | CloudTrail | **높음** – 감사 추적 부재 |
| CIS-2.2 | 2.2 | CloudTrail log integrity | 각 Trail에 로그 파일 검증 기능 활성화 | CloudTrail | **보통** – 로그 위·변조 탐지 실패 |
| CIS-2.3 | 2.3 | CloudTrail encryption | CloudTrail을 KMS CMK로 암호화 | CloudTrail | **보통** – 민감 이벤트 노출 |
| CIS-3.1 | 3.1 | Unauthorized API alerts | `AccessDenied`/`UnauthorizedOperation` 필터와 메트릭/알람 생성 | CloudWatch Logs | **보통** – 침해 탐지 지연 |
| CIS-4.1 | 4.1 | No open admin ports | 22/3389을 0.0.0.0/0에서 차단, 최소화된 보안 그룹 작성 | EC2 | **높음** – RDP/SSH 무차별 공격 |
| CIS-5.1 | 5.1 | Account-level PAB | 계정 퍼블릭 액세스 블록 4개 플래그 모두 활성화 | S3 | **높음** – 데이터 노출 위험 |

> 권장 Remediation 항목이 자동시정(AUTO_REMEDIATE=2) 가능한 항목에는 엔진이 안전 액션을 시도합니다. CloudTrail/KMS 관련 통제는 기본적으로 Dry-run으로 제한됩니다.
