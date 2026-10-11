import sqlite3
import tempfile
import unittest
from pathlib import Path

from mcp_authz_gateway.redact import redact, redact_text
from mcp_authz_gateway.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "g.db"
        self.s = Store(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_audit_chain_detects_tampering(self):
        for i in range(5):
            self.s.audit("fs", "read_file", "allow", "r", "ok", {"i": i})
        self.assertTrue(self.s.verify_audit()[0])
        con = sqlite3.connect(self.db)
        con.execute("UPDATE audit SET decision = 'deny' WHERE seq = 3")
        con.commit()
        ok, msg = self.s.verify_audit()
        self.assertFalse(ok)
        self.assertIn("3", msg)

    def test_audit_chain_detects_deletion(self):
        for i in range(4):
            self.s.audit("fs", "t", "allow", "r", "ok", {})
        con = sqlite3.connect(self.db)
        con.execute("DELETE FROM audit WHERE seq = 2")
        con.commit()
        self.assertFalse(self.s.verify_audit()[0])

    def test_approval_with_grant(self):
        aid = self.s.create_approval("fs", "write_file", {"path": "/x"}, "rule")
        self.assertEqual([p["id"] for p in self.s.pending()], [aid])
        self.assertTrue(self.s.decide(aid, True, grant_minutes=10))
        self.assertFalse(self.s.decide(aid, False))  # already decided
        self.assertIsNotNone(self.s.active_grant("fs", "write_file"))
        self.assertIsNone(self.s.active_grant("fs", "other"))
        gid = self.s.grants()[0]["id"]
        self.assertTrue(self.s.revoke(gid))
        self.assertIsNone(self.s.active_grant("fs", "write_file"))


class RedactTests(unittest.TestCase):
    def test_patterns(self):
        text = ("key AKIAABCDEFGHIJKLMNOP and ghp_" + "a" * 36 + " password=hunter22 "
                + "-----BEGIN RSA " + "PRIVATE KEY-----\nabc\n-----END RSA " + "PRIVATE KEY-----")
        out, n = redact_text(text)
        self.assertEqual(n, 4)
        for secret in ("AKIAABCDEFGHIJKLMNOP", "ghp_", "hunter22", "abc"):
            self.assertNotIn(secret, out)

    def test_sensitive_keys_masked_in_args_only(self):
        args = {"api_key": "plainvalue", "nested": [{"token": "t0k3n"}], "path": "/a"}
        out, n = redact(args)
        self.assertEqual(n, 2)
        self.assertEqual(out["path"], "/a")
        out2, n2 = redact(args, mask_keys=False)
        self.assertEqual(n2, 0)


if __name__ == "__main__":
    unittest.main()
