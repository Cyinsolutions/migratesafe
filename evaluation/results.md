# MigrateSafe fault-injection evaluation (simulated)

Tool version 0.1.0. All 14 checks were run unchanged against an in-memory world (DNS, HTTP, TLS, CT and RDAP are simulated); see `evaluation/world.py` and `evaluation/scenarios.py`.

- Injected faults: **28**; detected (expected check reports FAIL/WARN): **27** (96%)
- False positives on the correctly migrated baseline: **0** (none)
- 29 full audits in 0.16 s

| Threat | Detected / injected |
|---|---|
| T1 | 5 / 5 |
| T2 | 3 / 3 |
| T3 | 3 / 3 |
| T4 | 5 / 5 |
| T5 | 5 / 5 |
| T6 | 3 / 3 |
| T7 | 0 / 1 |
| T8 | 3 / 3 |

| Fault | Threat | Description | Expected check | Result | Flagged by | Detectable from |
|---|---|---|---|---|---|---|
| F01 | T1 | CNAME left in zone points to a de-provisioned host (NXDOMAIN target) | C2 | detected (FAIL) | C2 | P0 |
| F02 | T1 | CNAME to an unclaimed GitHub Pages site (takeover fingerprint) | C2 | detected (FAIL) | C2 | P0 |
| F03 | T1 | MX record points to a mail host that no longer exists | C2 | detected (FAIL) | C2 | P0 |
| F04 | T1 | Hostname visible only in CT logs is missing from the inventory | C1 | detected (FAIL) | C1 | P0 |
| F05 | T3 | Registrar still lists the former provider's nameserver (parent != zone NS) | C3 | detected (FAIL) | C3 | P2 |
| F06 | T3 | Delegated nameserver no longer serves the zone (lame delegation) | C3 | detected (FAIL) | C3 | P2 |
| F07 | T3 | Stale DS record after DNS-provider change (DNSSEC bogus) | C4 | detected (FAIL) | C4 | P2 |
| F08 | T4 | No CAA record on the new name | C5 | detected (FAIL) | C5 | P0 |
| F09 | T4 | CAA present but without an iodef contact | C5 | detected (WARN) | C5 | P0 |
| F10 | T4 | Certificate issued by an unexpected CA appears in CT | C6 | detected (FAIL) | C6 | P3 |
| F11 | T4 | New origin serves an expired or untrusted certificate | C7 | detected (FAIL) | C7 | P1 |
| F12 | T5 | New origin still accepts TLS 1.1 | C7 | detected (FAIL) | C7 | P1 |
| F13 | T4 | Former hosting provider still serves a valid certificate for the names | C8 | detected (FAIL) | C8 | P3 |
| F14 | T5 | No HSTS header on the new name | C9 | detected (FAIL) | C9 | P1 |
| F15 | T5 | HSTS max-age too short after stabilization | C9 | detected (WARN) | C9 | P1 |
| F16 | T2 | Old name keeps serving the legacy site instead of redirecting | C10 | detected (FAIL) | C10 | P2 |
| F17 | T5 | Old name uses a temporary redirect and drops the path | C10 | detected (WARN) | C10 | P2 |
| F18 | T8 | Legacy redirect builds its target from X-Forwarded-Host (open redirect) | C10 | detected (FAIL) | C10 | P2 |
| F19 | T1 | Session cookie scoped to the parent domain (Domain attribute) | C11 | detected (FAIL) | C11 | P1 |
| F20 | T5 | Session cookie without HttpOnly | C11 | detected (FAIL) | C11 | P1 |
| F21 | T8 | APP_URL still points to the old name | C12 | detected (FAIL) | C12 | P1 |
| F22 | T8 | CORS allow-list still contains the old origin | C12 | detected (FAIL) | C12 | P1 |
| F23 | T6 | SPF on the new name ends in ~all | C13 | detected (WARN) | C13 | P0 |
| F24 | T6 | No DMARC record on the new name | C13 | detected (FAIL) | C13 | P0 |
| F25 | T6 | Retired old name has no DMARC policy (spoofable) | C13 | detected (FAIL) | C13 | P0 |
| F26 | T2 | Old name registration expires in 20 days | C14 | detected (FAIL) | C14 | P0 |
| F27 | T2 | Old name has no transfer lock | C14 | detected (WARN) | C14 | P0 |
| F28 | T7 | A lookalike of the new name is registered | C14 | reported as INFO only | - | P0 |

Baseline status per check: C1 INFO, C2 PASS, C3 PASS, C4 PASS, C5 PASS, C6 INFO, C7 PASS, C8 PASS, C9 PASS, C10 PASS, C11 MANUAL, C12 MANUAL, C13 PASS, C14 MANUAL

## Limitations

- The faults were written by the tool's author from the threat model, so this measures whether the implementation covers the specified threats, not how often such faults occur in practice.
- Network behaviour is simulated. Real deployments add noise (CDN behaviour, crt.sh lag, registries without RDAP expiry data) that this experiment does not capture.
- Registered lookalike domains are deliberately reported as INFO, not WARN, because many are unrelated legitimate sites; F28 is therefore listed as reported, not flagged.
