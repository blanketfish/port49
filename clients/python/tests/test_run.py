"""The runner keeps no copy of the CLI's answer once run() returns or raises (#62), and still returns while a
grandchild of the CLI holds its stdout. Every token is made at runtime and never printed: the assertions are
booleans with words of their own, and leaks are found by walking objects, never by repr."""

import io
import os
import _thread
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

from port49 import _run, client  # noqa: E402
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


def thread_objects_hold(secret):
    """Whether any live thread but the main one reaches secret through its Thread object (its target and the
    target's closure)."""
    main = threading.main_thread()
    return any(t is not main and reaches(t, secret) for t in threading.enumerate())


def frames_hold(secret):
    """Whether a local of any frame on the stack of any thread but the main one reaches secret."""
    main = threading.main_thread()
    for ident, frame in sys._current_frames().items():
        while ident != main.ident and frame is not None:
            if reaches(dict(frame.f_locals), secret):
                return True
            frame = frame.f_back
    return False


def threads_hold(secret):
    """Whether any live thread but the main one reaches secret: its Thread object or a frame on its stack."""
    return thread_objects_hold(secret) or frames_hold(secret)


def wait_until_drain_settled(secret):
    """Block until the drain holds the answer in its closure and its frame has dropped the chunk it read: the
    state a Ctrl-C meets while a grandchild keeps the pipe open. Polls the state itself, never a fixed sleep.
    (A running thread has dropped its Thread._target, so the drain's closure shows only as free variables in
    its own frame's locals: the drain's frame is the one to look at.)"""

    def settled():
        for frame in sys._current_frames().values():
            if frame.f_code.co_name == "drain" and frame.f_code.co_filename == _run.run.__code__.co_filename:
                local = dict(frame.f_locals)
                return "chunk" not in local and reaches(local, secret)
        return False

    deadline = time.monotonic() + 10
    while not settled():
        if time.monotonic() > deadline:
            raise AssertionError("the drain never settled holding the answer")
        time.sleep(0.01)


TEST_CLOSURES = {"interrupted", "joined", "started"}  # the patched wait, join and start that raise below


class InterruptingLock:
    """A lock whose first use on the main thread waits for the drain to hold the answer, and whose first release
    there raises KeyboardInterrupt after the lock is let go: a Ctrl-C just after run's swap of the answer. It
    holds nothing of the test: the wait is a class attribute set by the test."""

    settle = None
    fired = False

    def __init__(self):
        self.real = _thread.allocate_lock()
        self.arm = False

    def __enter__(self):
        if threading.current_thread() is threading.main_thread() and not InterruptingLock.fired:
            self.arm = True
            InterruptingLock.settle()
        return self.real.acquire()

    def __exit__(self, *exc):
        self.real.release()
        if self.arm:
            self.arm = False
            InterruptingLock.fired = True
            raise KeyboardInterrupt


class InterruptedRan:
    """A Ran whose construction is interrupted: whatever run hands it is in this frame's locals."""

    def __init__(self, code, stdout, stderr_tail):
        raise KeyboardInterrupt


def frames_below_run(exc):
    """Every frame in exc's traceback from _run.run's own down to the raise (frames any helper run called
    holds too), or [] if run is not in it. The tests' own raising stand-ins named in TEST_CLOSURES are left
    out: their closure is the test case, which holds the secret."""
    tb, frames = exc.__traceback__, []
    while tb is not None:
        if frames or tb.tb_frame.f_code is _run.run.__code__:
            if tb.tb_frame.f_code.co_name not in TEST_CLOSURES:
                frames.append(tb.tb_frame)
        tb = tb.tb_next
    return frames


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

    def assert_unreachable(self, exc):
        """The answer is reachable from no frame of exc's traceback from run down, nor from any live thread."""
        frames = frames_below_run(exc)
        self.assertTrue(frames, "run's frame should be in the traceback")
        self.assertFalse(any(reaches(dict(f.f_locals), self.secret) for f in frames),
                         "a frame in the traceback, from run down, holds the answer")
        self.assertFalse(threads_hold(self.secret), "a live thread, or a frame on its stack, reaches the answer")

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
        self.assert_unreachable(caught)

    def test_an_interrupted_run_keeps_no_answer(self):
        real_wait = subprocess.Popen.wait

        def interrupted(proc, timeout=None):
            """The CLI exits, the drain has the answer and has dropped its chunk, and then Ctrl-C."""
            real_wait(proc)
            wait_until_drain_settled(self.secret)
            raise KeyboardInterrupt

        try:
            with mock.patch.object(subprocess.Popen, "wait", interrupted):
                _run.run([self.cli, "0"], stderr=self.err)
        except KeyboardInterrupt as e:
            caught = e
        else:
            self.fail("the run should have been interrupted")
        self.assert_unreachable(caught)

    def interrupt_in_reap(self, argv, **kwargs):
        """run() with a Ctrl-C in reap's join, once the drain holds the answer; the KeyboardInterrupt."""
        real_join = threading.Thread.join

        def joined(thread, timeout=None):
            real_join(thread, timeout)
            wait_until_drain_settled(self.secret)
            raise KeyboardInterrupt

        try:
            with mock.patch.object(threading.Thread, "join", joined):
                _run.run(argv, stderr=self.err, **kwargs)
        except KeyboardInterrupt as e:
            return e
        self.fail("the run should have been interrupted")

    def test_a_run_interrupted_in_reap_after_exit_keeps_no_answer(self):
        caught = self.interrupt_in_reap([self.cli, "0"])
        self.assert_unreachable(caught)

    def test_a_run_interrupted_in_reap_after_timeout_keeps_no_answer(self):
        caught = self.interrupt_in_reap([self.cli, "30"], timeout=3.0)
        self.assert_unreachable(caught)

    def test_a_run_interrupted_while_the_readers_start_keeps_no_answer(self):
        real_start, starts = threading.Thread.start, []

        def started(thread):
            real_start(thread)
            starts.append(thread)
            if len(starts) == 2:  # the drain is running: the pump started first
                wait_until_drain_settled(self.secret)
                raise KeyboardInterrupt

        try:
            with mock.patch.object(threading.Thread, "start", started):
                _run.run([self.cli, "0"], stderr=self.err)
        except KeyboardInterrupt as e:
            caught = e
        else:
            self.fail("the run should have been interrupted")
        self.assert_unreachable(caught)

    def test_a_run_interrupted_just_after_the_swap_keeps_no_answer(self):
        """Ctrl-C as the lock that guards the answer's handoff is let go."""
        InterruptingLock.fired = False
        self.addCleanup(setattr, InterruptingLock, "settle", None)
        InterruptingLock.settle = staticmethod(lambda: wait_until_drain_settled(self.secret))
        try:
            shim = types.SimpleNamespace(Lock=InterruptingLock, Thread=threading.Thread)  # only run's own lock
            with mock.patch.object(_run, "threading", shim):
                _run.run([self.cli, "0"], stderr=self.err)
        except KeyboardInterrupt as e:
            caught = e
        else:
            self.fail("the run should have been interrupted")
        self.assertTrue(InterruptingLock.fired, "the interrupt should have fired in the handoff")
        self.assert_unreachable(caught)

    def test_a_run_interrupted_in_building_its_result_keeps_no_answer(self):
        try:
            with mock.patch.object(_run, "Ran", InterruptedRan):
                _run.run([self.cli, "0"], stderr=self.err)
        except KeyboardInterrupt as e:
            caught = e
        else:
            self.fail("the run should have been interrupted")
        self.assert_unreachable(caught)

    def test_a_truncated_answer_never_reads_as_an_answer(self):
        """run cannot tell a prefix from a whole answer while a grandchild holds the pipe (no EOF), so the
        parse must fail closed: no proper prefix of a JSON object is itself a JSON object."""
        whole = b'{"verdict": "permit", "login": "' + self.secret + b'", "detail": {"a": [1, 2]}}\n'
        reads = [client.answer(_run.Ran(0, bytearray(whole[:n]), "")) is not None for n in range(len(whole) - 1)]
        self.assertFalse(any(reads), "a truncated answer parsed as an answer")
        self.assertTrue(client.answer(_run.Ran(0, bytearray(whole), "")) is not None, "the whole answer should parse")


if __name__ == "__main__":
    unittest.main()
