# Security Policy

## Supported Versions
MiniCSPM is currently distributed as source. Security updates are released on the main branch and tagged builds.

| Version | Supported |
|---------|-----------|
| main    | ✅        |
| tags < 0.1.0 | ❌ |

## Reporting a Vulnerability
1. Email `security@mini-cspm.example.com` with a detailed description, reproduction steps, and impact assessment.
2. Encrypt sensitive reports using our PGP key (fingerprint available upon request).
3. We target an initial response within **72 hours**, and will coordinate disclosure once a fix is available.

## Secure Development Practices
- Secrets must never be committed—use environment variables or AWS Secrets Manager.
- All pull requests must pass `pip-audit`, `make lint`, and `pytest` before merge.
- New AWS permissions must be documented in `docs/CONTROLS.md` and approved by the security lead.
