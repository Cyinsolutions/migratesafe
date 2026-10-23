# Changelog

## 0.1.0 – 2026-10-23

First public release.

- Fourteen read-only checks (C1–C14) from the MigrateSafe paper: zone inventory, dangling targets,
  delegation, DNSSEC, CAA, Certificate Transparency, TLS, former-host keys, HSTS, legacy redirect,
  session cookies, configuration drift (including Laravel `.env`), e-mail authentication, and
  retention/lookalikes.
- Phase-aware audits (`--phase P0` … `P4`), JSON reports, and CI-friendly exit codes.
- Fault-injection evaluation harness (`python3 -m evaluation.run`): 28 faults, 27 flagged by the
  expected check, 0 false positives on the baseline.
