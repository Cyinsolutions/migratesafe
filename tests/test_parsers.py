import os
import tempfile
import unittest

from migratesafe import parsers as P
from migratesafe.checks import checks_for_phase, scan_project
from migratesafe.model import FAIL, PASS, WARN, Result, worst


class HstsTest(unittest.TestCase):
    def test_full(self):
        h = P.parse_hsts("max-age=31536000; includeSubDomains; preload")
        self.assertEqual((h.max_age, h.include_subdomains, h.preload), (31536000, True, True))

    def test_quoted_and_missing(self):
        self.assertEqual(P.parse_hsts('max-age="300"').max_age, 300)
        self.assertIsNone(P.parse_hsts("includeSubDomains"))
        self.assertIsNone(P.parse_hsts(None))


class MailTest(unittest.TestCase):
    def test_spf(self):
        recs = ['"v=spf1 include:_spf.google.com" " -all"', '"google-site-verification=x"']
        spf = P.find_spf(recs)
        self.assertEqual(len(spf), 1)
        self.assertEqual(P.spf_all_qualifier(spf[0]), "-")
        self.assertEqual(P.spf_all_qualifier("v=spf1 a mx ~all"), "~")
        self.assertEqual(P.spf_all_qualifier("v=spf1 a mx all"), "+")
        self.assertIsNone(P.spf_all_qualifier("v=spf1 a mx"))
        self.assertTrue(P.is_null_spf("v=spf1 -all"))
        self.assertFalse(P.is_null_spf("v=spf1 mx -all"))

    def test_dmarc(self):
        d = P.parse_dmarc(['"v=DMARC1; p=reject; rua=mailto:d@example.com"'])
        self.assertEqual(d["p"], "reject")
        self.assertIn("rua", d)
        self.assertIsNone(P.parse_dmarc(['"v=spf1 -all"']))

    def test_null_mx(self):
        self.assertTrue(P.is_null_mx(["0 ."]))
        self.assertFalse(P.is_null_mx(["10 mail.example.com."]))


class CaaTest(unittest.TestCase):
    def test_parse(self):
        caa = P.parse_caa(['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.com"'])
        self.assertEqual([c.tag for c in caa], ["issue", "iodef"])
        self.assertEqual(caa[0].value, "letsencrypt.org")

    def test_issuer_mapping(self):
        org = P.issuer_org("C=US, O=Let's Encrypt, CN=R11")
        self.assertEqual(org, "Let's Encrypt")
        self.assertEqual(P.issuer_caa_id(org), "letsencrypt.org")
        self.assertEqual(P.issuer_caa_id("Google Trust Services"), "pki.goog")


class CookieTest(unittest.TestCase):
    def statuses(self, header):
        return [s for s, _ in P.evaluate_cookie(P.parse_set_cookie(header))]

    def test_good_session(self):
        self.assertEqual(self.statuses("laravel_session=x; path=/; secure; httponly; samesite=lax"), ["PASS"])

    def test_wildcard_domain_session_fails(self):
        st = self.statuses("laravel_session=x; Domain=.old.example; secure; httponly; samesite=lax")
        self.assertIn("FAIL", st)

    def test_missing_httponly(self):
        self.assertIn("FAIL", self.statuses("PHPSESSID=x; secure; samesite=strict"))

    def test_csrf_may_be_readable(self):
        self.assertEqual(self.statuses("XSRF-TOKEN=x; secure; samesite=lax"), ["PASS"])

    def test_infra_cookie_ignored(self):
        self.assertEqual(self.statuses("__cf_bm=x; Domain=example.com; HttpOnly"), ["INFO"])


class LegacyTlsTest(unittest.TestCase):
    def test_classification(self):
        c = P.classify_legacy_tls
        self.assertEqual(c(True, None), "accepted")
        self.assertEqual(c(False, "SSLError: [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version"), "refused")
        self.assertEqual(c(False, "ConnectionResetError: [Errno 54] Connection reset by peer"), "refused")
        self.assertEqual(c(False, "SSLEOFError: EOF occurred in violation of protocol"), "refused")
        self.assertEqual(c(False, "SSLError: [SSL: NO_PROTOCOLS_AVAILABLE] no protocols available"), "unknown")
        self.assertEqual(c(False, "TimeoutError: timed out"), "unknown")


class RedirectTest(unittest.TestCase):
    probe = "/migratesafe-probe/path?q=1"

    def test_good_chain(self):
        chain = [(301, "https://old.example/migratesafe-probe/path?q=1"),
                 (301, "https://new.example/migratesafe-probe/path?q=1")]
        self.assertEqual([s for s, _ in P.evaluate_redirect_chain(chain, "new.example", self.probe)], ["PASS"])

    def test_wrong_host_and_302(self):
        chain = [(302, "https://evil.example/")]
        st = [s for s, _ in P.evaluate_redirect_chain(chain, "new.example", self.probe)]
        self.assertIn("FAIL", st)
        self.assertIn("WARN", st)

    def test_no_redirect(self):
        self.assertEqual(P.evaluate_redirect_chain([], "new.example", self.probe)[0][0], "FAIL")


class TakeoverTest(unittest.TestCase):
    def test_fingerprint(self):
        self.assertEqual(P.takeover_suffix("acme.github.io."), "github.io")
        self.assertIsNotNone(P.takeover_fingerprint("acme.github.io", "<h1>There isn't a GitHub Pages site here.</h1>"))
        self.assertIsNone(P.takeover_fingerprint("acme.github.io", "Welcome"))
        self.assertIsNone(P.takeover_suffix("github.io.evil.example"))


class LookalikeTest(unittest.TestCase):
    def test_candidates(self):
        c = P.lookalike_candidates("crypto311.com")
        self.assertIn("crypto311.net", c)
        self.assertIn("crypt311.com", c)
        self.assertNotIn("crypto311.com", c)
        self.assertLessEqual(len(c), 40)

    def test_split(self):
        self.assertEqual(P.split_domain("shop.example.co.in"), ("shop.example", "co.in"))


class EnvTest(unittest.TestCase):
    def test_laravel(self):
        env = P.parse_env("APP_URL=https://old.example\nSESSION_DOMAIN=.old.example\n"
                          "SESSION_SECURE_COOKIE=false\nSANCTUM_STATEFUL_DOMAINS=old.example,new.example\n")
        st = [s for s, _ in P.evaluate_laravel_env(env, "new.example", "old.example")]
        self.assertEqual(st.count("FAIL"), 4)

    def test_mask(self):
        self.assertEqual(P.mask_env_line("APP_KEY=base64:abc"), "APP_KEY=****")
        self.assertEqual(P.mask_env_line("APP_URL=https://x"), "APP_URL=https://x")

    def test_scan_project_masks_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".env"), "w") as f:
                f.write("MAIL_PASSWORD=old.example-secret\nAPP_URL=https://old.example\n")
            os.makedirs(os.path.join(d, "node_modules"))
            with open(os.path.join(d, "node_modules", "x.js"), "w") as f:
                f.write("old.example")
            hits = scan_project(d, "old.example", [])
            self.assertEqual(len(hits), 2)
            self.assertTrue(any("MAIL_PASSWORD=****" in h for h in hits))
            self.assertFalse(any("secret" in h for h in hits))


class ModelTest(unittest.TestCase):
    def test_worst_and_phases(self):
        self.assertEqual(worst([PASS, WARN, FAIL]), FAIL)
        r = Result("C1", "t", "T1")
        r.add(PASS, "a", "ok")
        r.add(WARN, "b", "hm")
        self.assertEqual(r.status, WARN)
        self.assertEqual(checks_for_phase("P0"), ["C1", "C2", "C5", "C13", "C14"])
        self.assertEqual(len(checks_for_phase("P4")), 14)


if __name__ == "__main__":
    unittest.main()
