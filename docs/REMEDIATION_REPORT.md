# Remediation Report — Ledgerly

**Scope:** Ledgerly, a Flask invoicing app, reviewed against the OWASP Top 10 (2021).
**Method:** each finding was identified, a fixed implementation written, a regression test added
that fails on the vulnerable behavior and passes on the fix, and — where the flaw is a detectable
code pattern — a Semgrep rule added so CI blocks its return.

## Findings

| ID | Finding | OWASP | CWE | Severity | Status | Verified by |
| --- | --- | --- | --- | --- | --- | --- |
| [F01](../findings/F01.md) | SQL Injection | A03 Injection | CWE-89 | Critical | Fixed | test + Semgrep |
| [F02](../findings/F02.md) | Broken Access Control (IDOR) | A01 Broken Access Control | CWE-639 | High | Fixed | test |
| [F03](../findings/F03.md) | Stored XSS | A03 Injection | CWE-79 | High | Fixed | test + Semgrep |
| [F04](../findings/F04.md) | SSRF | A10 SSRF | CWE-918 | High | Fixed | test + Semgrep |
| [F05](../findings/F05.md) | Insecure Password Storage | A02 Cryptographic Failures | CWE-916 | High | Fixed | test + Semgrep |
| [F06](../findings/F06.md) | Security Misconfiguration | A05 Security Misconfiguration | CWE-16 | Medium | Fixed | test |

**Severity summary:** 1 Critical, 4 High, 1 Medium — all remediated and verified.

## How each fix is kept from regressing

1. **Regression tests** (`tests/`): 18 tests assert the secure behavior. A revert to the vulnerable
   code fails the relevant test.
2. **Static analysis** (`semgrep/rules.yaml`): 5 rules catch the insecure *pattern* (string-built
   SQL, unescaped rendering, SSRF on user input, weak password hashing, debug mode) before it
   merges. The rules themselves are tested (`semgrep --test`).
3. **Dependency + general scanning**: `pip-audit` for known CVEs in dependencies, `bandit` for
   common insecure Python patterns.

All four run in CI on every push; the build fails on any finding.

## Note on scope

This project demonstrates the **remediation and prevention** half of a pen test: the fixes,
the verification, and the controls that stop each issue returning. The findings are modeled on
the OWASP Top 10 rather than discovered against a live target. The methodology — reproduce,
remediate, regression-test, add a detection rule, retest — is the same one used to close findings
from a real engagement.
