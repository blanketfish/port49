"""The library against the real port49 binary, built here: no hand-written JSON for what it can print.

With no agent listening the CLI answers for itself, so these need no broker. A host with no Go
toolchain skips them; make test has one."""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from port49 import Agent, NoAgent, Port49Error  # noqa: E402

REPO = os.path.join(HERE, "..", "..", "..")


class RealCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        go = shutil.which("go")
        if go is None:
            raise unittest.SkipTest("no go toolchain to build the port49 binary")
        cls.dir = tempfile.mkdtemp()
        cls.binary = os.path.join(cls.dir, "port49")
        built = subprocess.run([go, "build", "-o", cls.binary, "./cmd/port49"], cwd=REPO,
                               env={**os.environ, "CGO_ENABLED": "0"}, capture_output=True, text=True)
        if built.returncode != 0:
            raise AssertionError("go build ./cmd/port49 failed:\n" + built.stderr)
        cls.socket = os.path.join(cls.dir, "no-agent.sock")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def agent(self):
        return Agent(port49=self.binary, socket=self.socket, stderr=io.StringIO())

    def test_no_agent_is_no_agent(self):
        with self.assertRaises(NoAgent) as cm:
            self.agent().token("leaf1")
        self.assertEqual((cm.exception.code, cm.exception.device), ("no_agent", "leaf1"))
        self.assertIn("no agent is listening", cm.exception.detail)

    def test_a_sweep_stops_at_no_agent(self):
        with self.assertRaises(NoAgent):
            self.agent().tokens(["leaf1", "leaf2"])

    def test_identity_with_no_agent_says_so(self):
        with self.assertRaises(Port49Error) as cm:
            self.agent().identity()
        self.assertIn("no agent", cm.exception.detail)


if __name__ == "__main__":
    unittest.main()
