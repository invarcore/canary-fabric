# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in CanaryFabric, please report it responsibly:

1. **Email**: Send details to `sagarv.kumar48@gmail.com` with the subject line `[SECURITY] CanaryFabric Vulnerability Report`.
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours of receiving the report.
- **Assessment**: Within 7 days, we will confirm the vulnerability and assess severity.
- **Fix**: Critical vulnerabilities will be patched within 14 days. A security advisory will be published once a fix is available.

## Scope

The following are in scope for security reports:

- Cryptographic weaknesses in HMAC token derivation or signature verification
- Bypass of the circuit breaker or streaming watcher
- Injection attacks through zero-width character manipulation
- SQLite vault tampering or data integrity issues
- Honeytoken false-negative scenarios (undetected leaks)

## Out of Scope

- Denial-of-service attacks against the reverse proxy (use rate limiting)
- Social engineering attacks
- Vulnerabilities in upstream dependencies (report those to the respective maintainers)

## Acknowledgments

We appreciate responsible disclosure and will credit reporters in the CHANGELOG (with their consent).