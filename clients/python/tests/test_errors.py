import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from port49 import Denied, DeviceFault, MFARequired, Port49Error  # noqa: E402

EVIL = "evil\x1b]0;PWNED\x07\x1b[2J\n\r\x9b\x7f"


def clean(text):
    return all(c.isprintable() for c in text)


class NoControlBytes(unittest.TestCase):
    """A device name, code, reason or detail comes from inventory or the CLI's JSON: no str() of an
    exception may carry a terminal control byte (an OSC title, a screen clear, a forged line)."""

    def test_every_class_prints_clean(self):
        errs = [Port49Error("co\x1bde", "detail\nforged: ok", EVIL),
                DeviceFault("device_unconfigured", "d\x07", EVIL),
                Denied("deny", "d\x1b", EVIL, reason="r\x1b[31m", verdict="v\n"),
                MFARequired("per_login_mfa_required", "d\r", EVIL, requirement={"accept": ["a\x1b"]})]
        for e in errs:
            self.assertTrue(clean(str(e)), repr(str(e)))
            self.assertTrue(clean(e.args[0]), repr(e.args[0]))
            self.assertIn("?", str(e))

    def test_ordinary_text_is_untouched(self):
        e = Denied("deny", "no grant", "leaf1", reason="no_grants_matched")
        self.assertEqual(str(e), "port49: leaf1: deny no_grants_matched: no grant")


if __name__ == "__main__":
    unittest.main()
