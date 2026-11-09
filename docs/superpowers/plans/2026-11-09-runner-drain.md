# Runner drain keeps no answer (#62) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Once `_run.run` returns or raises, nothing the runner made holds the CLI's answer, whatever a grandchild of the CLI does with its stdout. The run still returns about a second after the CLI exits while a grandchild holds the pipe, as it does today.

**Architecture:** The drain thread stops owning the answer. It fills a buffer held in a one-slot list under a lock. `run` takes the buffer out of the slot (`take()`) after the bounded join, on every path out: return, timeout, and any other exception. After that the drain keeps reading and drops what it reads, and it deletes each chunk before its next blocking read. No caller changes, no Go change, no Ansible change, no new dependency. No lab run.

**Tech Stack:** Python 3.10+, standard library only (`clients/python/pyproject.toml`: `dependencies = []`), stdlib `unittest` under `make test-python`; the README is included in the docs site (`docs/site/operate/install/clients.md:61`), checked by `make docs` and `go test ./tests/ci/`.

**Issue:** #62. The issue cites `_run.py:456-469`; the file is 100 lines on `main` `906e8c93`, and the code it means is `clients/python/src/port49/_run.py:44-100`.

## Root cause (investigation 2026-11-09, `main` `906e8c93`)

1. **What holds the answer after `run` returns.**
   - `_run.py:45`: `out_buf = bytearray()` is a cell variable of `run`. `drain` (`:64-73`) closes over it and appends every chunk it reads. `run` returns that same object in `Ran.stdout` (`:100`).
   - `reap` (`:79-87`) joins each reader for `REAP` (1.0 s) and closes the pipes only if both readers are done. A grandchild that inherited the CLI's stdout keeps the write end open, so `drain` never sees EOF. It stays blocked in `os.read` (`:66`), and `run` returns without it.
   - While it is blocked, the answer is reachable three ways, none through anything `run` returned:
     - **The thread object.** `threading.enumerate()` lists it. `Thread.run` keeps `self._target` (the `drain` function) until the target returns, and `drain.__closure__` holds `out_buf`.
     - **The frame's locals.** `sys._current_frames()` gives the blocked frame. Its `f_locals` holds the free variable `out_buf` and the local `chunk`, the last bytes read. A CLI answer under 64 KiB is one read, so `chunk` is the whole answer, a second copy that clearing `out_buf` would not touch.
     - **A traceback's frame.** On the timeout path (`:91-95`), `raise Port49Error(...)` leaves `run`'s frame in the traceback, and that frame's `f_locals` holds `out_buf` with whatever the killed CLI printed. This happens with or without a grandchild. A `KeyboardInterrupt` during `p.wait` leaves the same frame, and an interactive session keeps it in `sys.last_traceback`.
   - Measured on `906e8c93` with a throwaway script in the scratchpad: a fake CLI prints a generated token, starts `sleep` with stdout inherited, and exits. `run` returned in under 3 s, and both the drain's closure and its frame's `chunk` held the token. Nothing was printed but booleans.
2. **For how long.** Until the grandchild closes stdout or exits. That has no bound.
3. **Who leaves such a grandchild.** The `port49` binary itself does not. Its detached children get a log file or `/dev/null`: the login agent (`cmd/port49/main.go:743-746`, `cmd.Stdout = logf`) and the browser (`cmd/port49/issue.go:672-673`, nil `Stdout`, which Go opens as `/dev/null`). The exposure needs `port49=` to name a wrapper whose background job inherits stdout. Examples are a shell wrapper's `cmd &`, which `test_agent.py:231-241` already models, or a daemon a wrapper starts without redirecting stdout, such as a credential cache or a version-manager shim. Modern OpenSSH's `ControlPersist` master sends its stdout to `/dev/null` when it detaches, so it is not a case here unless a wrapper runs it in the foreground. We have not measured it, and the plan does not depend on it.
4. **What the drain protects against today.** The drain runs on a thread, with a bounded join, so that `run` returns after the CLI exits even while a grandchild holds the pipe. That behavior has to stay. The thread also keeps reading, so a grandchild that writes to the pipe never blocks on a full pipe buffer and never gets `SIGPIPE`.
5. **Callers.** `client.py:135` (`Agent.identity`), `:156` (`Agent._once`), `:222` (`Workload.identity`) and `:262` (`Workload._once`) read `Ran.stdout` once, through `answer()` (`:78-84`). Each holds `ran` only in its own frame. `netmiko.connect` and the Ansible lookup (`clients/ansible/.../plugins/lookup/token.py:97-104`) mint through `Agent` and `Workload`. `hostkeys.py` uses `subprocess.run` for `ssh -G` and `ssh-keygen`, which return no token. None of these needs a change.

## Rulings made in this plan

1. **The drain stops holding the answer and discards what comes after. It does not close the pipe.**
   - The other option was to close our read end once the CLI exits, which would let the drain thread end. It loses on three counts:
     - **The grandchild pays.** Its next write to that stdout gets `SIGPIPE`, which kills it by default. A user's background helper then dies on its first stray write, with nothing in port49's output to explain it.
     - **It is unsafe as written.** Closing a descriptor while another thread is blocked in `os.read` on it does not wake that thread on Linux. The number can then be reused, and the read lands on the wrong file. `reap`'s docstring already rules this out. Doing it safely needs `select` on the pipe plus a wake pipe: more code, for the cost above.
     - **There is nothing to bound.** A "bounded EOF/length" read has no length to bound: the CLI's answer has no length prefix, and EOF is exactly what the grandchild withholds. `MAX_STDOUT` already bounds memory.
   - Discarding keeps today's timing and today's treatment of the grandchild. Only what the thread holds changes.
2. **`take()` is the handoff, on every path out of `run`.** The buffer sits in `held = [bytearray()]`, guarded by a `threading.Lock`. `take()` swaps in `None` and returns the buffer.
   - **Return:** `run` calls `reap()` first, so the drain has its `REAP` second to read the CLI's last bytes, and then `answer = take()`. The answer is complete whenever it was complete before. As a side effect, a late write from a grandchild can no longer change the returned `Ran.stdout` after `run` returns.
   - **Timeout:** `reap()`, then `take()` with the result discarded, then `raise`.
   - **Any other exception** (`KeyboardInterrupt` during `p.wait`): `take()`, then `raise`. This path does not reap or kill, the same as today, so Ctrl-C stays immediate.
   - The drain counts `size` and appends only while `held[0]` is not `None`. So nothing a grandchild prints after the handoff can trip `answer_too_large`.
3. **The drain deletes each chunk before its next read** (`del chunk`). Its blocked frame then holds no part of the answer. Without this, clearing the buffer would still leave the token in the frame's locals.
4. **No zeroing and no caller change.** The guarantee is about reachability. Python cannot zero the `str` copies `json.loads` makes, and the `Token` the caller asked for holds the token by design. Zeroing the one bytearray would protect nothing a memory dump could not find elsewhere. `Ran.stdout` stays a `bytearray`, the same object the drain filled.
5. **What stays as it is.** A run whose pipe a grandchild holds still leaves one thread and two descriptors behind until the grandchild closes them, and still waits `REAP` per reader (see Left for later). The thread now holds nothing.
6. **Tests generate every token at runtime** with `secrets.token_urlsafe(18)`. The token is stored on `self` and in a 0700 `mkdtemp` file the fake CLI reads, and the directory is removed in cleanup. No assertion prints it: leaks are checked with booleans and token-free messages, by walking objects, never `repr`. No test uses `assertRaises` where the traceback matters. The test's leak walk reads only the threads other than the main one, and `_run.run`'s own frame in a caught exception's traceback. The test's own frames hold `self` and are not the runner's.
7. **The grandchild is the test's to clean up.** The fake CLI writes the grandchild's PID to a file. `addCleanup` kills that PID with `SIGKILL`, never by name (no `pkill`, no `pgrep`). The grandchild also exits by itself after 20 s, so a crashed test leaves nothing for long.
8. **No lab run.** No device behavior changes, and no §15 row is involved.

## What an operator sees at 3am

| Event | Before | After |
|---|---|---|
| `port49=` names a wrapper whose background job keeps stdout open, and a script mints 500 tokens | Each run's raw answer, token included, stays in memory and is reachable through `threading.enumerate()` for as long as the job lives. An error tracker or debugger that walks threads can record it | Each run's drain thread lingers, as before, but holds nothing |
| A run times out after the CLI printed part of its answer | The traceback's `run` frame holds what was printed. An error tracker that captures locals stores it | The `run` frame holds no answer |
| Ctrl-C during a run in a notebook | `sys.last_traceback` keeps the partial answer | It keeps none |
| Timing with such a wrapper | Returns about 1 s after the CLI exits | Unchanged |

## Global Constraints

- Python 3.10+ floor, standard library only (`pyproject.toml` `dependencies = []`). `make test-python` runs without paramiko in CI. For local runs, `/home/rwendt/lab-venv/bin/python` has paramiko and netmiko.
- Match `_run.py`'s style: short comments that say why, long lines up to the file's existing width.
- No Go change, no Ansible change, no reason code, config key, warning or metric.
- **No token in logs, messages, test output or fixtures.** Never print a token while debugging a test, even a fake one. Assert on it instead (Ruling 6).
- **Security rules, repeated in every implementer brief:**
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, or key, secret or token files. Never `cat /tmp/port49-lab-tokens.jsonl`.
  - Every recursive grep excludes them. grep is ugrep: use `-e PATTERN`, never `--` before a pattern. Never grep `tests/lab/logs` or `tests/lab/captures`.
  - Never run `port49 token`, `port49 workload token` or any real mint. The tests use their own fake CLI.
  - Never `pkill` or `pgrep`. Kill only a PID the test recorded (Ruling 7).
  - If a safety check refuses a command, stop and report it. Never rephrase it.
  - Edit repo files with the Edit/Write tools only, never sed, perl, python or heredocs.
- **Tests:**
  - Run tests in the foreground only.
  - On this host `/tmp` is tmpfs. `TMPDIR` is a short private directory on ext4: `export TMPDIR=$(mktemp -d ~/.cache/p49t.XXXX) && chmod 700 $TMPDIR`.
  - Per task, run `make test-python`, plus `go test ./tests/ci/ -count=1` when docs change.
  - The final task runs `make test && make vet && make docs && make test-rest`, then `make test-python` and `go test ./tests/ci/ -count=1`, all under that TMPDIR. `git status --short` after `make docs` shows no diff.
  - If a test fails for a reason this plan does not name, report it. Do not fix it in passing.
- **Commits:**
  - Conventional Commits, one per task, with an explicit pathspec.
  - Every message ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and nothing else. No `Claude-Session:` line, and no claude.ai URL anywhere: commits, PR body, comments.
- **Branch:** `fix/drain-62`, from `main` `906e8c93`, in `.worktrees/drain-62`. Tasks run in order.
- **Lab:** none (Ruling 8).

## Review Focus

1. **Every path out of `run` hands the buffer off.** That means the return, `timeout`, `answer_too_large`, and the `BaseException` clause. Check that no local of `run` other than the returned `answer` is bound to the buffer when `run` leaves. Check the same for the drain's frame: no `chunk`, and no local alias of `held[0]`.
2. **The answer is still complete.** `take()` runs after `reap()` on the return path. A test asserts that the answer came back byte for byte.
3. **The drain never blocks the grandchild.** After the handoff it keeps reading and drops what it reads. It never closes the pipe while it is blocked in a read (Ruling 1).
4. **The tests never print or `repr` a token,** and never use `assertRaises` around a traceback they inspect. The grandchild is killed by its recorded PID.

---

### Task 1: the drain hands the answer to `run` and keeps nothing (Rulings 1–3)

**Files:**
- Create `clients/python/tests/test_run.py`.
- Modify `clients/python/src/port49/_run.py` (`:44-100`).

**Interfaces (unchanged):** `run(argv, *, stdin=None, timeout=None, stderr=None, oversize_hint="") -> Ran`. `Ran(code, stdout, stderr_tail)`, where `stdout` is a `bytearray`. `REAP = 1.0`, `MAX_STDOUT = 64 << 20`.

- [ ] **Step 1: Write the failing tests.** Create `clients/python/tests/test_run.py`:

  ```python
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
  ```

- [ ] **Step 2: Run them and see red.** Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v clients/python/tests/test_run.py` from the worktree root.
  - Expected on `906e8c93`: three fail.
    - `test_a_returned_run_leaves_no_thread_holding_the_answer`: "a live thread, or a frame on its stack, reaches the answer".
    - `test_a_timed_out_run_keeps_no_answer` and `test_an_interrupted_run_keeps_no_answer`: "run's frame in the traceback holds the answer".
  - `test_a_run_returns_whole_while_a_grandchild_holds_stdout` passes. It guards behavior that must not regress.
  - Paste the failure lines into the task report. They hold no token: the messages are the test's own.

- [ ] **Step 3: Make the drain hand the answer off.** In `_run.py`, replace `out_buf = bytearray()  # one copy: ...` (`:45`) and `drain` (`:64-73`) with:

  ```python
      lock = threading.Lock()
      held = [bytearray()]  # the answer: the drain's until take() hands it to run, then [None] (#62)
  ```

  and

  ```python
      def drain():
          while True:
              chunk = os.read(p.stdout.fileno(), 65536)
              if not chunk:
                  return
              with lock:
                  if held[0] is not None:  # once run has the answer, a grandchild's writes are read and dropped
                      size[0] += len(chunk)
                      if size[0] <= MAX_STDOUT:
                          held[0].extend(chunk)
                      else:
                          held[0].clear()  # over the cap: keep draining, hold nothing
              del chunk  # blocked in the next read, this frame holds no part of the answer

      def take():
          """The answer, handed from the drain to run: the drain keeps no reference to it after. One copy:
          the answer is parsed from it as it is."""
          with lock:
              answer, held[0] = held[0], None
          return answer
  ```

  Replace the tail of `run` (`:89-100`) with:

  ```python
      try:
          code = p.wait(timeout=timeout)
      except subprocess.TimeoutExpired:
          p.kill()
          p.wait()
          reap()
          take()  # what the ended run printed goes with no one: this frame is in the traceback
          raise Port49Error("timeout", f"{argv[0]} {argv[1]} did not finish within {timeout}s and was ended") from None
      except BaseException:  # an interrupt mid-wait: its traceback holds this frame, never the answer
          take()
          raise
      reap()
      answer = take()  # after reap: the drain has had its REAP to read the CLI's last bytes
      if size[0] > MAX_STDOUT:  # the drain cleared the answer at the cap: answer is empty
          raise Port49Error("answer_too_large", f"{argv[0]} {argv[1]} printed more than {MAX_STDOUT} bytes and the "
                            f"answer was dropped (it exited {code}, and may have minted){oversize_hint}")
      return Ran(code, answer, printable(tail.decode("utf-8", "replace"), TAIL))
  ```

  Leave `pump`, `reap`, the thread start and the module docstring as they are. Then add one sentence to the docstring's first paragraph, after "on success it holds a token.": `Once run returns or raises, the drain thread holds none of it, though a grandchild keeps the pipe open (#62).`

- [ ] **Step 4: Run them and see green.** Run the Step 2 command: all four pass. Then run `make test-python`: every test passes, including `test_agent.py`'s `test_a_wrapper_that_leaves_a_grandchild_does_not_hold_the_timeout`, `test_an_answer_over_the_cap_is_an_error_of_its_own`, and `test_workload.py`'s cap and fleet-sized-answer tests.

- [ ] **Step 5: Mutations.** Make each change with Edit. Run the Step 2 command, record the result, then revert with Edit. Each must go red where stated, with the test's own message:

  | # | Mutation | Red |
  |---|---|---|
  | M1 | Delete the line `del chunk  # blocked in the next read, ...` | `test_a_returned_run_leaves_no_thread_holding_the_answer` (the frame's `chunk`) |
  | M2 | In `take()`, replace `answer, held[0] = held[0], None` with `answer = held[0]` | `test_a_returned_run_leaves_no_thread_holding_the_answer` (the closure) |
  | M3 | Delete the `take()` line in the `TimeoutExpired` handler | `test_a_timed_out_run_keeps_no_answer` |
  | M4 | Delete the `except BaseException:` clause (both lines under it too) | `test_an_interrupted_run_keeps_no_answer` |
  | M5 | Set `REAP = 10.0` | `test_a_run_returns_whole_while_a_grandchild_holds_stdout` ("the run waited on the grandchild") |

  After reverting all five, `git diff` shows only Step 1's and Step 3's changes, and the Step 2 command is green.

- [ ] **Step 6: Commit.**

  ```bash
  git add clients/python/src/port49/_run.py clients/python/tests/test_run.py
  git commit -m "fix(python): the runner's drain keeps no copy of the CLI's answer once run returns or raises (#62)

  A grandchild holding the CLI's stdout kept the drain thread alive with the
  answer in its closure and its last chunk in a frame local, reachable through
  threading.enumerate(). A timeout's or an interrupt's traceback held it in
  run's frame. The drain now hands the buffer to run on every path out and
  drops what it reads after; it never closes the pipe under a grandchild.

  Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
  ```

### Task 2: the README says the reader keeps nothing

**Files:**
- Modify `clients/python/README.md` (`## Secrets`, `:185-196`).

- [ ] **Step 1: Edit.** In `## Secrets`, after the sentence "No exception, `repr` or failed-parse error carries the CLI's stdout." insert:

  > Once a call returns or raises, the library keeps no copy of the CLI's stdout, even if a program the CLI started (a wrapper's background job) holds that stdout open: the library reads and drops whatever that program prints until it closes it, and never closes the pipe under it.

- [ ] **Step 2: Check.** Run `grep -rn --exclude=realm.json --exclude='*.env' --exclude='*-key.pem' --exclude='*.keytab' -e 'holds that stdout open' clients/python/README.md docs/site`. The only hit is the README. The docs site includes it through `docs/site/operate/install/clients.md:61` and holds no copy of its own. Then run `go test ./tests/ci/ -count=1` and `make docs` under the TMPDIR. Both pass, and `git status --short` shows only the README.

- [ ] **Step 3: Commit.**

  ```bash
  git add clients/python/README.md
  git commit -m "docs(python): the library keeps no copy of the CLI's stdout once a call returns (#62)

  Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
  ```

### Task 3: Final verification

- [ ] Under the Global Constraints TMPDIR, run `make test && make vet && make docs && make test-rest`, then `make test-python` and `go test ./tests/ci/ -count=1`, then `git status --short`. Paste the summary lines. If a test fails for a reason this plan does not name, report it. Do not fix it in passing.
- [ ] Run `grep -n -e 'out_buf' clients/python/src/port49/_run.py`. Expect no hit.
- [ ] Run `grep -rn --exclude=realm.json --exclude='*.env' --exclude='*-key.pem' --exclude='*.keytab' -e 'pkill' -e 'pgrep' -e 'print(' clients/python/tests/test_run.py`. Expect no hit.

## Operator-facing notes for the PR body

- **Python client: no copy of a token outlives the call.** If `port49=` named a wrapper that leaves a background job holding the CLI's stdout, every mint's raw answer, token included, stayed in memory. It was reachable through the library's reader thread (`threading.enumerate()`) for as long as the job lived. A timed-out or interrupted run also left what the CLI had printed in its traceback. An error tracker or debugger that walks threads or records locals could store it. Now the reader hands the answer over and keeps nothing.
- **Nothing else changes.** A run with such a wrapper still returns about a second after the CLI exits, and the background job keeps its stdout: the library reads and drops what it prints, and never closes the pipe under it. The `port49` binary itself starts no such job.
- No server, CLI, Ansible or config change. No lab run.

## Left for later

- **The lingering reader.** A run whose pipe a grandchild holds still leaves one thread and two descriptors until the grandchild closes them, and waits `REAP` (1 s) for each reader. Over a long `Agent.tokens` sweep through such a wrapper, that is one thread, two descriptors and up to 2 s per device. Ending the thread means closing our read end, and that sends `SIGPIPE` to the grandchild on its next write (Ruling 1). A fix needs its own design, and probably a doc line telling users to redirect a wrapper's background job.
