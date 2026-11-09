"""The runner keeps no copy of the CLI's answer once run() returns or raises (#62), and still returns while a
grandchild of the CLI holds its stdout. Every token is made at runtime and never printed: the assertions are
booleans with words of their own, and leaks are found by walking objects, never by repr."""

import io
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from port49 import _run  # noqa: E402
from port49.errors import Port49Error  # noqa: E402

# A CLI that prints its answer, leaves a grandchild holding its stdout (and nothing else of the run's), records
# the grandchild's PID, then sleeps argv[1] seconds. The grandchild ends itself after 20 s.
CLI = """#!{python}
import os, subprocess, sys, time
d = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(d, "answer"), "rb") as f:
    sys.stdout.buffer.write(f.read())
sys.stdout.buffer.flush()
kid = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"], stdin=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
with open(os.path.join(d, "grandchild.pid"), "w", encoding="utf-8") as f:
    f.write(str(kid.pid))
time.sleep(float(sys.argv[1]))
"""


def reaches(root, secret):
    """Whether secret (bytes) is reachable from root through attributes, slots, containers, closures and bound
    methods."""
    seen, todo = {}, [root]  # seen keeps each object alive, so an id is never reused mid-walk
    while todo:
        obj = todo.pop()
        if id(obj) in seen or isinstance(obj, (types.ModuleType, type)):
            continue
        seen[id(obj)] = obj
        if isinstance(obj, (bytes, bytearray)):
            if secret in obj:
                return True
            continue
        if isinstance(obj, str):
            if secret.decode() in obj:
                return True
            continue
        if isinstance(obj, dict):
            todo += [x for kv in obj.items() for x in kv]
        elif isinstance(obj, (list, tuple, set, frozenset)):
            todo += list(obj)
        if isinstance(obj, types.FunctionType):
            for cell in obj.__closure__ or ():
                try:
                    todo.append(cell.cell_contents)
                except ValueError:  # an empty cell
                    pass
            todo += [obj.__defaults__, obj.__kwdefaults__]
        elif isinstance(obj, types.MethodType):
            todo += [obj.__self__, obj.__func__]
        try:
            d = getattr(obj, "__dict__", None)
        except Exception:
            d = None
        if isinstance(d, dict):
            todo.append(d)
        for slot in getattr(type(obj), "__slots__", ()):
            try:
                todo.append(getattr(obj, slot, None))
            except Exception:
                pass
    return False


def threads_hold(secret):
    """Whether any live thread but the main one reaches secret: its Thread object (its target and the target's
    closure) or a local of any frame on its stack."""
    main = threading.main_thread()
    if any(t is not main and reaches(t, secret) for t in threading.enumerate()):
        return True
    for ident, frame in sys._current_frames().items():
        while ident != main.ident and frame is not None:
            if reaches(dict(frame.f_locals), secret):
                return True
            frame = frame.f_back
    return False


def run_frame(exc):
    """_run.run's own frame in exc's traceback, or None."""
    tb = exc.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code is _run.run.__code__:
            return tb.tb_frame
        tb = tb.tb_next
    return None


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()  # 0700
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.addCleanup(self.kill_grandchild)  # runs first: cleanups are last in, first out
        self.secret = secrets.token_urlsafe(18).encode()  # on self, never in a frame the walk reads
        self.answer = b'{"login": "' + self.secret + b'"}\n'
        with open(os.path.join(self.dir, "answer"), "wb") as f:
            f.write(self.answer)
        self.cli = os.path.join(self.dir, "cli")
        with open(self.cli, "w", encoding="utf-8") as f:
            f.write(CLI.format(python=sys.executable))
        os.chmod(self.cli, 0o700)
        self.err = io.StringIO()

    def pid(self):
        with open(os.path.join(self.dir, "grandchild.pid"), encoding="utf-8") as f:
            return int(f.read())

    def kill_grandchild(self):
        """Kill the PID the CLI recorded, if it recorded one: never by name."""
        try:
            pid = self.pid()
        except (OSError, ValueError):
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def grandchild_alive(self):
        try:
            os.kill(self.pid(), 0)
        except ProcessLookupError:
            return False
        return True

    def test_a_returned_run_leaves_no_thread_holding_the_answer(self):  # #62
        ran = _run.run([self.cli, "0"], stderr=self.err)
        self.assertTrue(self.grandchild_alive(), "the grandchild should still hold stdout")
        self.assertTrue(self.secret in ran.stdout, "the run should return the answer")
        self.assertFalse(threads_hold(self.secret), "a live thread, or a frame on its stack, reaches the answer")

    def test_a_run_returns_whole_while_a_grandchild_holds_stdout(self):
        began = time.monotonic()
        ran = _run.run([self.cli, "0"], stderr=self.err)
        took = time.monotonic() - began
        self.assertTrue(self.grandchild_alive(), "the grandchild should still hold stdout")
        self.assertLess(took, 4.0, "the run waited on the grandchild")
        self.assertEqual(ran.code, 0)
        self.assertTrue(bytes(ran.stdout) == self.answer, "the answer should come back whole and alone")

    def test_a_timed_out_run_keeps_no_answer(self):
        try:
            _run.run([self.cli, "30"], timeout=3.0, stderr=self.err)
        except Port49Error as e:
            caught = e
        else:
            self.fail("the run should have timed out")
        self.assertEqual(caught.code, "timeout")
        self.assertTrue(os.path.exists(os.path.join(self.dir, "grandchild.pid")),
                        "the CLI should have printed its answer before the timeout")
        frame = run_frame(caught)
        self.assertIsNotNone(frame, "run's frame should be in the traceback")
        self.assertFalse(reaches(dict(frame.f_locals), self.secret), "run's frame in the traceback holds the answer")
        self.assertFalse(threads_hold(self.secret), "a live thread, or a frame on its stack, reaches the answer")

    def test_an_interrupted_run_keeps_no_answer(self):
        real_wait = subprocess.Popen.wait

        def interrupted(proc, timeout=None):
            """The CLI exits, the drain has the answer, and then Ctrl-C."""
            real_wait(proc)
            deadline = time.monotonic() + 10
            while not threads_hold(self.secret):
                if time.monotonic() > deadline:
                    raise AssertionError("the drain never read the answer")
                time.sleep(0.01)
            raise KeyboardInterrupt

        try:
            with mock.patch.object(subprocess.Popen, "wait", interrupted):
                _run.run([self.cli, "0"], stderr=self.err)
        except KeyboardInterrupt as e:
            caught = e
        else:
            self.fail("the run should have been interrupted")
        frame = run_frame(caught)
        self.assertIsNotNone(frame, "run's frame should be in the traceback")
        self.assertFalse(reaches(dict(frame.f_locals), self.secret), "run's frame in the traceback holds the answer")
        self.assertFalse(threads_hold(self.secret), "a live thread, or a frame on its stack, reaches the answer")


if __name__ == "__main__":
    unittest.main()
