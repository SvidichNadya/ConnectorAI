import datetime
import http.server
import ipaddress
import random
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import dataclasses
from dcpm.errors import DCPMError
from dcpm.security.netguard import SafeFetcher
from dcpm.security.untrusted import sanitize
from dcpm.security.urls import Scope, normalize_url
from tests.support import TEST_POLICY


def make_cert(dirname, names):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    cp, kp = f"{dirname}/c.pem", f"{dirname}/k.pem"
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cp, kp


class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert, key = make_cert(cls.tmp.name, ["secure.test"])

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.cert, key)
        cls.srv.socket = ctx.wrap_socket(cls.srv.socket, server_side=True)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close(); cls.tmp.cleanup()

    def fetcher(self, **pol):
        return SafeFetcher(dataclasses.replace(TEST_POLICY, **pol), resolver=lambda h, p: ["127.0.0.1"])

    def test_untrusted_certificate_is_rejected(self):
        with self.assertRaises(DCPMError) as c:
            self.fetcher().fetch(f"https://secure.test:{self.port}/", scope=Scope(("secure.test",)))
        self.assertEqual(c.exception.code, "TLS_ERROR")

    def test_trusted_ca_works_with_pinned_ip_and_sni(self):
        r = self.fetcher(ca_bundle=self.cert).fetch(f"https://secure.test:{self.port}/", scope=Scope(("secure.test",)))
        self.assertEqual(r.body, b"ok")

    def test_hostname_mismatch_is_rejected(self):
        # certificate is valid for secure.test only; connecting to the same IP under another name must fail
        with self.assertRaises(DCPMError) as c:
            self.fetcher(ca_bundle=self.cert).fetch(f"https://other.test:{self.port}/", scope=Scope(("other.test",)))
        self.assertEqual(c.exception.code, "TLS_ERROR")

    def test_downgrade_redirect_refused(self):
        # exercised via the redirect logic: https -> http
        from dcpm.security import netguard
        f = self.fetcher(ca_bundle=self.cert)
        calls = []
        orig = f._single_request
        def fake(nu, ips, method, extra, max_bytes, deadline):
            calls.append(nu.scheme)
            return 302, {"location": "http://secure.test/x"}, b""
        f._single_request = fake
        with self.assertRaises(DCPMError) as c:
            f.fetch("https://secure.test/", scope=Scope(("secure.test",)))
        self.assertEqual(c.exception.code, "POLICY_BLOCKED")
        self.assertEqual(calls, ["https"])


class FuzzTests(unittest.TestCase):
    def test_normalize_url_never_raises_foreign_exceptions_and_is_idempotent(self):
        rnd = random.Random(1234)
        alphabet = "abcXYZ019:/?#[]@%.-_~&=+;,\\ \t\r\n\x00é中\u202e"
        seeds = ["http://", "https://a.b/", "http://[", "http://%", "https://a.b:80x/", "//a.b", "HTTP://A.B:443/%zz?x=%"]
        for i in range(6000):
            base = rnd.choice(seeds)
            s = base + "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
            try:
                n = normalize_url(s)
            except DCPMError:
                continue
            # accepted URLs are clean ASCII with no whitespace/control chars, and normalising again is a fixpoint
            self.assertTrue(n.url.isascii() and not any(ord(ch) <= 32 or ch == "\\" for ch in n.url), s)
            self.assertEqual(normalize_url(n.url).url, n.url, s)

    def test_sanitize_is_total(self):
        rnd = random.Random(7)
        for _ in range(500):
            obj = [rnd.choice(["x" * 1000, None, 1.5, {"a": ["\x00" * 5]}, (1, 2), {1, 2}, object()]) for _ in range(30)]
            sanitize(obj)


if __name__ == "__main__":
    unittest.main()
