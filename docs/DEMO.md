# Demo Playbook

이 가이드는 의도적으로 잘못 구성된 AWS 계정을 대상으로 MiniCSPM을 실행하고, 자동시정 전후의 상태를 비교하는 실습 흐름을 제공합니다.

## 1. 데모 환경 구성
다음과 같은 취약 구성을 준비합니다 (Terraform/CloudFormation 또는 수동 설정 사용):
- **보안 그룹**: `sg-demo`에 포트 22, 3389가 `0.0.0.0/0`으로 개방되어 있음.
- **S3 퍼블릭 액세스 블록**: 계정 수준 PAB 비활성화 (`BlockPublicPolicy=false`).
- **IAM 비밀번호 정책**: 최소 길이 8, 기호 미요구, 재사용 제한 없음.

이 상태에서 `aws sts get-caller-identity`로 데모 계정을 확인해 둡니다.

## 2. 초기 스캔 (Auto-Remediation 비활성화)
```bash
export AUTO_REMEDIATE=0
python -m minicspm.cli scan --format json --out demo/before.json
python -m minicspm.cli scan --format csv --out demo/before.csv
```

요약 확인:
```bash
python -m minicspm.cli score --from demo/before.json
python -m minicspm.cli findings --from demo/before.json
```

예상 결과:
- 점수: PASS 3 / FAIL 7 → Weighted 30점 수준.
- `demo/before.csv`에는 SG, PAB, 비밀번호 정책 실패가 기록됩니다.

## 3. 자동시정 Dry-Run
안전한 자동시정을 미리 검토합니다.
```bash
export AUTO_REMEDIATE=1
python -m minicspm.cli scan --format json --out demo/dryrun.json
```

`demo/dryrun.json`의 각 FAIL evidence에 `remediations` 배열이 추가되며 `mode=DRY_RUN`, `applied=false`로 표시됩니다. 이를 통해 실제 변경 없이 예정된 조치를 검토합니다.

## 4. 자동시정 적용
```bash
export AUTO_REMEDIATE=2
python -m minicspm.cli scan --format json --out demo/after.json
python -m minicspm.cli findings --from demo/after.json
```

적용 후 검증:
- SG에서 22/3389 오픈 규칙 제거 (`describe-security-groups` 확인).
- `s3control get-public-access-block` 결과가 4개 플래그 모두 `true`.
- `iam get-account-password-policy`가 강력한 정책으로 교체.

`demo/after.json`에서 동일한 컨트롤이 `mode=APPLY`, `applied=true`로 기록되고, FAIL → PASS 전환이 반영됩니다.

## 5. CSV 비교
```bash
diff -u demo/before.csv demo/after.csv || true
```

변경 요약 예시:
```
- 2024-01-01T00:00:00Z,123456789012,CIS-4.1,...,FAIL,...
+ 2024-01-01T00:05:00Z,123456789012,CIS-4.1,...,PASS,...
```

## 6. AWS 배포 시연 (선택)
1. `sam build && sam deploy`로 Lambda/이벤트/리포트 버킷을 배포합니다.
2. EventBridge 스케줄이 동작한 후 DynamoDB `MiniCspmResults` 테이블에서 최신 실행을 확인하고, S3 보고서를 다운로드합니다.
3. CloudWatch Logs에서 자동시정 결과와 presigned URL 로그를 확인합니다.

이 데모 흐름은 보안팀이 변경 승인 전후 증적을 확보하고, 안전 조치가 실제로 적용되는지 검증하는 데 활용할 수 있습니다.
