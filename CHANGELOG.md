# Changelog

## 0.1.1 – 2026-10-23

- C7: the TLS 1.0/1.1 probe now works on Python builds linked against OpenSSL 3, which refuse
  legacy protocols at the default security level (it previously reported "could not test").
- C7: a server that resets the connection when only TLS 1.0/1.1 is offered is now correctly
  reported as refusing legacy TLS. Verified against badssl.com's TLS 1.0/1.1/1.2 endpoints.

## 0.1.0 – 2026-10-23

First public release.

- Fourteen read-only checks (C1–C14) from the MigrateSafe paper: zone inventory, dangling targets,
  delegation, DNSSEC, CAA, Certificate Transparency, TLS, former-host keys, HSTS, legacy redirect,
  session cookies, configuration drift (including Laravel `.env`), e-mail authentication, and
  retention/lookalikes.
- Phase-aware audits (`--phase P0` … `P4`), JSON reports, and CI-friendly exit codes.
- Fault-injection evaluation harness (`python3 -m evaluation.run`): 28 faults, 27 flagged by the
  expected check, 0 false positives on the baseline.
