# MigrateSafe

[![tests](https://github.com/myabhya/migratesafe/actions/workflows/tests.yml/badge.svg)](https://github.com/myabhya/migratesafe/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/migratesafe)](https://pypi.org/project/migratesafe/)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23576774.svg)](https://doi.org/10.5281/zenodo.23576774)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Read-only security audit for domain migrations.**

When a web platform moves from `old.example` to `new.example`, there is a window in which two names,
two hosting environments and two sets of DNS, TLS and e-mail settings coexist. MigrateSafe checks
that window for dangling records, certificate anomalies, transport/session downgrades, spoofable mail,
broken redirects and configuration drift.

It implements the fourteen verification checks (C1–C14) from:

> A. A. More, “MigrateSafe: A threat model and verification framework for secure domain migration of
> web-hosted cryptocurrency trading platforms,” Zenodo, preprint, Oct. 2026,
> doi: [10.5281/zenodo.23576774](https://doi.org/10.5281/zenodo.23576774).

## Install

Requires Python 3.9+ and [dnspython](https://www.dnspython.org/).

```bash
pip install migratesafe
```

Or run from a checkout without installing (dnspython must be available):

```bash
python3 -m migratesafe audit --new new.example --old old.example
```

## Usage

```bash
# full audit of a completed migration
migratesafe audit --new new.example --old old.example

# only the checks that matter up to a given phase (P0 preparation ... P4 retirement)
migratesafe audit --new new.example --old old.example --phase P1

# a subset of checks, with a JSON report for CI or record keeping
migratesafe audit --new new.example --checks C5,C9,C13 --json report.json

# include a scan of the application source for leftover references to the old name
migratesafe audit --new new.example --old old.example --project ~/code/exchange --config migratesafe.json

migratesafe list
```

Exit codes: `0` all passed, `1` warnings or errors, `2` at least one failure, which makes it usable as a CI gate.

## Checks

| ID | Check | Threats | How it is verified |
|----|-------|---------|--------------------|
| C1 | Zone inventory | T1, T2 | Hostnames from CT logs (crt.sh) and common-name probing are compared with your inventory |
| C2 | Dangling targets | T1 | CNAME/MX/NS targets that no longer resolve; known takeover fingerprints on SaaS targets |
| C3 | Delegation | T3 | Parent NS set equals zone NS set; every nameserver answers authoritatively |
| C4 | DNSSEC | T3 | DS at parent and AD-validated answers, or a documented exception |
| C5 | CAA | T4 | `issue`/`issuewild` restrict CAs and an `iodef` contact exists |
| C6 | CT audit | T1, T4 | Recent certificates are from allowed issuers / permitted by CAA |
| C7 | New-origin TLS | T4, T5 | Valid chain, expiry, SAN scope, TLS 1.0/1.1 refused |
| C8 | Former-host keys | T4 | The former host no longer serves a trusted certificate for your names |
| C9 | HSTS | T5 | `max-age` ≥ 1 year with `includeSubDomains` from phase P3 |
| C10 | Legacy redirect | T5, T8 | 301/308 to `https://new`, path preserved, no open redirect |
| C11 | Session cookies | T1, T5 | Host-only, `Secure`, `HttpOnly`, `SameSite` |
| C12 | Allow-lists and configuration | T2, T8 | Source scan for the old name; Laravel `.env` checks (`APP_URL`, `SESSION_DOMAIN`, ...) |
| C13 | E-mail authentication | T2, T6 | SPF `-all`, DKIM, DMARC `p=reject`; Null MX + `v=spf1 -all` on a retired name |
| C14 | Retention and lookalikes | T2, T7 | RDAP expiry and transfer lock; registered typo/TLD lookalikes |

Threat classes: T1 dangling records / subdomain takeover, T2 residual trust, T3 delegation hijack,
T4 certificate anomalies, T5 transport/session downgrade, T6 e-mail spoofing, T7 lookalike domains,
T8 configuration drift.

CT data comes from the public crt.sh service, which can lag behind the logs by hours and occasionally
returns incomplete results; treat C1/C6 output as a lower bound and re-run if crt.sh is unavailable.

Some things cannot be observed from outside (revoked sessions, provider dashboards, registrar MFA);
those are reported as `MANUAL` items so they still appear on the checklist.

## Configuration (optional)

See [`example-config.json`](example-config.json):

```json
{
  "inventory": {"new.example": "migrate", "www.new.example": "migrate", "status.old.example": "delete"},
  "allowed_issuers": ["Let's Encrypt"],
  "dkim_selectors": ["default"],
  "old_host_ip": "203.0.113.10",
  "dnssec_exception": false,
  "old_domain_mail": "retired",
  "session_paths": ["/", "/login"],
  "config_ignore": ["CHANGELOG.md"]
}
```

## Safety and ethics

MigrateSafe is **read-only**. It performs ordinary DNS queries, HTTPS requests and TLS handshakes, and reads
public CT and RDAP data. It never claims resources, requests certificates or modifies anything. Values of
secret-looking keys are masked when `.env` lines are reported. Only audit domains you own or are
authorised to test.

## Evaluation (fault injection)

`evaluation/` runs all fourteen checks, unchanged, against a simulated Internet (DNS, HTTP, TLS, CT and RDAP
in memory). It starts from a correctly migrated baseline and injects 28 faults covering threats T1–T8:

```bash
python3 -m evaluation.run      # writes evaluation/results.md and results.json
```

Current result: 27/28 faults flagged by the expected check, 1 (registered lookalike) reported as INFO by
design, and 0 false positives on the baseline. See [`evaluation/results.md`](evaluation/results.md) for the
per-fault table and limitations.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Author

Er. Abhijeet Ashok More (myabhya). Director, Cyin Solutions Pvt Ltd; Founder, Sumantrak.
ORCID [0009-0001-4934-0204](https://orcid.org/0009-0001-4934-0204) ·
[Google Scholar](https://scholar.google.com/citations?user=uF97rbsAAAAJ) ·
[LinkedIn](https://www.linkedin.com/in/myabhya/)

## Citation

```bibtex
@misc{more2026migratesafe,
  author       = {More, Abhijeet Ashok},
  title        = {MigrateSafe: A Threat Model and Verification Framework for Secure Domain
                  Migration of Web-Hosted Cryptocurrency Trading Platforms},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.23576774},
  note         = {Preprint}
}
```

## License

MIT, see [LICENSE](LICENSE).
