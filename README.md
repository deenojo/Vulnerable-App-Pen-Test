# Web App Pen Test → Remediation Playbook

Taking common web-app pen-test findings and **closing them so they stay closed**: for each OWASP
Top 10 issue there's a fix, a regression test that proves the fix, and a static-analysis rule that
fails CI if the vulnerability comes back.

[![security-ci](https://github.com/deenojo/Vulnerable-App-Pen-Test/actions/workflows/ci.yml/badge.svg)](https://github.com/deenojo/Vulnerable-App-Pen-Test/actions/workflows/ci.yml)

Companion security projects: **[Patchwarden](https://github.com/deenojo/Vulnerability-Remediation-Agent)** ·
**[PromptWall](https://github.com/deenojo/PromptWall)** · **[TenantGuard](https://github.com/deenojo/TenantGuard)**

## Results

| | |
| --- | --- |
| Findings remediated | **6** (1 Critical, 4 High, 1 Medium) across 5 OWASP Top 10 categories |
| Regression tests | **18**, all passing — each asserts the control, not just the happy path |
| Detection rules | **5** Semgrep rules, each self-tested with `semgrep --test` |
| Scanners in CI | pytest · Semgrep · Bandit · pip-audit, all green |

Full writeup: **[docs/REMEDIATION_REPORT.md](docs/REMEDIATION_REPORT.md)**.

## Findings

| ID | Finding | OWASP / CWE | Fix | Kept closed by |
| --- | --- | --- | --- | --- |
| [F01](findings/F01.md) | SQL Injection | A03 / CWE-89 | Parameterized queries | test + `formatted-sql-string` |
| [F02](findings/F02.md) | Broken Access Control (IDOR) | A01 / CWE-639 | Object-level authorization | test |
| [F03](findings/F03.md) | Stored XSS | A03 / CWE-79 | Output escaping + CSP | test + `jinja-unescaped-output` |
| [F04](findings/F04.md) | SSRF | A10 / CWE-918 | URL allowlist + public-IP check | test + `ssrf-request-from-user-input` |
| [F05](findings/F05.md) | Insecure Password Storage | A02 / CWE-916 | bcrypt + per-password salt | test + `weak-password-hash` |
| [F06](findings/F06.md) | Security Misconfiguration | A05 / CWE-16 | Headers, secret via env, secure cookies | test + `flask-debug-enabled` |

## The loop, per finding

1. **Reproduce** the issue and state its impact.
2. **Remediate** with a fixed implementation (in `app/`).
3. **Regression-test** the control (in `tests/`) so a revert fails the build.
4. **Add a detection rule** (in `semgrep/rules.yaml`) so the insecure *pattern* can't merge again.
5. **Retest**: the whole suite runs green in CI.

`app/ledgerly.py` is a small Flask invoicing app that is the **fixed** reference — every route
demonstrates a control. `app/security.py` holds the reusable pieces (password hashing, SSRF URL
validation).

## Run it

```bash
pip install -r requirements-dev.txt
pytest -q                                              # 18 regression tests
semgrep --test --config semgrep/rules.yaml semgrep/rules.py   # the detectors work
semgrep --config semgrep/rules.yaml app/               # 0 findings on the fixed app
bandit -r app/                                         # 0 issues
pip-audit -r requirements.txt                          # 0 known CVEs
```

## Scope and honesty

This is the **remediation and prevention** half of a pen test — the half that actually reduces
risk. The findings are modeled on the OWASP Top 10 rather than discovered against a live target,
and the vulnerable app is reconstructed only as the *fixed* version plus tests and detection rules
(no runnable exploit code is shipped). The methodology is identical to closing findings from a
real engagement: reproduce, fix, regression-test, add a guardrail, retest.
