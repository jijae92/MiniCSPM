# 통제 매핑 표

| Control ID | Service | CIS v1.5 | CIS v5.0 | Severity |
|------------|---------|-----------|-----------|----------|
| CIS-1.1 | IAM | Root account MFA enabled | Root account MFA enabled | HIGH |
| CIS-1.2 | IAM | Root access keys rotated/removed | Root access keys rotated/removed | HIGH |
| CIS-1.3 | IAM | Root access key rotation reminder | – | HIGH |
| CIS-1.5 | IAM | Strong password policy >=14 chars | Strong password policy >=14 chars | MEDIUM |
| CIS-1.14 | IAM | – | IAM Access Analyzer enabled | MEDIUM |
| CIS-1.18 | Security Hub | – | GuardDuty detector + Security Hub on | HIGH |
| CIS-1.22 | IAM | MFA for console users | MFA for console users | HIGH |
| CIS-2.1 | CloudTrail | Organization/multi-region CloudTrail enabled | Organization/multi-region CloudTrail enabled | HIGH |
| CIS-2.4 | CloudTrail | – | CloudTrail data events logging on buckets/functions | MEDIUM |
| CIS-3.1 | CloudWatch Logs | Unauthorized API metric filter & alarm | Unauthorized API metric filter & alarm | MEDIUM |
| CIS-3.2 | CloudWatch Alarms | – | Root account API alarm configured | HIGH |
| CIS-4.1 | EC2 | No 0.0.0.0/0 on SSH/RDP security groups | No 0.0.0.0/0 on SSH/RDP security groups | HIGH |
| CIS-5.1 | S3 | Account-level Block Public Access enabled | Account-level Block Public Access enabled | HIGH |

> `–` 표시는 해당 벤치마크 버전에서 요구되지 않는 통제입니다.
