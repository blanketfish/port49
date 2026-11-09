# Workload-backed Netmiko (#56) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Python workload, such as an automation job or an AI agent with its own machine identity, can run device commands through `port49.netmiko.connect(device, workload=port49.Workload(...))`. The token goes from the mint to the Netmiko connection and nowhere else, on both the Workload and the Agent path.

**Architecture:** `connect` gains a `workload=` keyword. A private `_mint` picks the source: `Workload.tokens([device])` or `Agent.token(device)`. A Workload's per-device refusal raises what the Agent path raises. `connect` becomes a thin wrapper over `_connect`. On any exception the wrapper clears the locals of every frame in the traceback chain, up to the caller's own exception. The pin's refresh closure keeps the address and username, not the `Token`. No Go change, no Ansible change, no new reason code, warning, config key or metric. No lab run.

**Tech Stack:** Python 3.10+, standard library only (`clients/python/pyproject.toml`: `dependencies = []`, `netmiko` an extra), stdlib `unittest` under `make test-python`; MkDocs pages under `docs/site`, checked by `go test ./tests/ci/`.

**Issue:** #56.

## Root causes (investigation 2026-11-09, `main` `012542a6`)

1. **connect mints only through a person's agent.**
   - `clients/python/src/port49/netmiko.py:186-195`: `tok = (agent or Agent()).token(device, enable=enable)`.
   - `Workload` (`client.py:200-280`) has `identity()` and `tokens(devices=None, scope=None, enable=False, ttl=None, purpose=None)`, and no `token()`. So `connect(..., agent=Workload(...))` fails with `AttributeError` after nothing is minted. There is no other device path in the library.
   - `Workload.tokens([device])` already gives everything connect reads: `Token.of(it)` (`client.py:43-47`) takes `device`, `address`, `platform`, `username`, `login`, `enable` from the broker's item (`internal/broker/api/api.go:106-110`). `--enable` passes through (`client.py:239`). Host keys are connect's own, after the mint (`netmiko.py:205-213`), and need nothing from the mint path.
   - A per-device refusal comes back in `res.refused` as a `Refusal`. `Refusal.exception()` (`client.py:59-61`) goes through `error_for` (`:87-104`), the function `Agent._once` uses. So a deny is `Denied`, a second factor (the broker's `per_login_mfa_required` deny, including a workload whose `touch_key` proof was not made) is `MFARequired`, and a broker fault is `DeviceFault`, the same classes as the Agent path.
   - A run that stopped raises from `tokens()` with `.results` (`client.py:243-246`). `.results` may hold tokens. Today a caller of `Workload.tokens` owns them. Through connect, they would reach the caller.
2. **The token already leaks from connect on the Agent path, in two places.**
   - **A closure.** `netmiko.py:247-248` passes `lambda: hostkeys.lookup(device, tok.address, ...)` as the pin's `refresh`. The lambda closes over `tok`, so `conn.key_policy.refresh.__closure__` holds the `Token`, and its `.login`, for the life of the connection. That is an attribute path the caller can read, beyond Netmiko's own `password` and `secret`.
   - **Traceback locals.** A failure after the mint re-raises from `connect` (`netmiko.py:249-271`). The traceback holds connect's frame (`tok`), and Netmiko's and Paramiko's frames below it. Paramiko's `connect` and its auth handlers hold `password` as a plain `str` local. `Token`'s `repr=False` hides `login` from `repr(tok)`, but not from a `str` local. A traceback printed with `capture_locals=True`, or captured by an error tracker that records locals, shows the token. `HostKeyError(...) from None` suppresses the context when printed, but `__context__` still holds the chain and its frames.
   - `Agent._once` (`client.py:153-162`) and `Workload._once` (`:249-280`) already keep the raw answer in their own frame for this reason, and `test_agent.py:222-229` asserts it for `Agent.token`. connect never got the same rule.
3. **The docs say Python workloads have no device path.**
   - `docs/site/agents/quick-start.md:23-31` (rule 3) names `port49.Workload` as something "which only mints", and `:189-190` allows only Ansible `network_cli`.
   - `docs/site/agents/setup-runbook.md:103-107`: "`port49.Workload` only mints: it runs no device command, and `port49.netmiko.connect` uses a person's session ... port49 ships no connector for it. Use the Ansible play here."
   - `clients/python/README.md:108-114` (included in `docs/site/operate/install/clients.md:61`) shows only the Agent form. `netmiko.py:1-6` says "The token comes from your agent".
   - `docs/site/admin/workloads.md`, `docs/site/concepts/identities.md` and the reference pages say nothing about a Python device path (grepped: `netmiko`, `port49.Workload`, `Workload(`).
   - Spec §13 decision 46 ruling 16 (`docs/design/2026-08-23-policy-engine-spec.md:10190`) and design §17's client table (`docs/design/2026-08-21-port49-design.md:2442`) name `connect` without saying whose token it takes.
   - `tests/ci/docs_content_22_test.go:14-18` requires `"port49.Workload"`, ``"Never use `port49.Agent`"`` and `"never eAPI"` on the quick-start. This plan keeps all three and adds two.
4. **The Ansible lookup is not affected.** `clients/ansible/.../plugins/lookup/token.py` mints for Ansible's own `network_cli` connection and never calls `port49.netmiko`. It needs no change.

## Rulings made in this plan

1. **A `workload=` keyword, not a shared minting interface.**
   - The alternative was a `Workload.token(device)` that `agent=` would accept. It loses on four counts:
     - It adds a public single-device mint that returns a `Token` to any caller, for no gain.
     - It erases the person/machine line in the call. The quick-start's rule is then a grep: `workload=` is required, and `agent=` and `port49.Agent` are forbidden.
     - It makes both-given impossible to detect.
     - It makes two different contracts look alike. `Agent.token` retries what sent nothing, and a Workload run is never rerun (decision 46 ruling 11). A shared interface invites a retry wrapper that would mint a page twice.
   - The new signature is `connect(device, *, enable=False, agent=None, workload=None, ssh_config=None, **netmiko_kwargs)`. Netmiko has no `workload` argument, so nothing is shadowed.
2. **Fail closed before any mint.**
   - `agent=` and `workload=` together raise `ValueError`.
   - A `Workload` passed as `agent=` raises `TypeError` (today that is an `AttributeError`).
   - Anything but a `port49.Workload` as `workload=` raises `TypeError`, so a person's `Agent` cannot be passed off as a workload.
   - Neither given keeps today's `Agent()`, so a person's script is unchanged. With no agent running, its `NoAgent` is re-raised with the same code and the CLI's detail, and adds: "a program with a machine identity of its own passes workload=port49.Workload(...) instead". An explicit `agent=` keeps its `NoAgent` unchanged.
3. **One `port49 workload token` run per `connect`, for the one device, never rerun.** `ttl` and `purpose` are not added. `ttl` keeps parity with the Agent path, which passes none, so `token_ttl` from policy applies. `purpose` is left for later. A device in neither `tokens` nor `refused` is `DeviceFault("no_token", ...)`, the code the README already lists for "minted it no token".
4. **A stopped run's error leaves connect without tokens.** Before re-raising, `_mint` replaces `.results` with `results.without_tokens()` (`client.py:69-71`). The device names and refusals stay. The caller of `connect` asked for a connection, not tokens.
5. **The token never reaches the caller, on both paths.**
   - On any `BaseException`, `connect` clears the locals of every frame in the exception's traceback, and in its causes' and contexts' tracebacks (`traceback.clear_frames`). It stops at the exception the caller was handling when it called `connect` (`sys.exc_info()[1]` on entry), so the caller's own frames keep their locals.
   - The pin's refresh closes over `address` and `username`, not `tok`.
   - The connection holds the token only as Netmiko's `password` and `secret`. Netmiko needs them to log in again (`establish_connection()`, SCP), so they stay, and the docs tell an agent never to read or print them.
   - Fixing the Agent path is in scope: the issue's "the token should never reach the caller" is a property of `connect`, and the Workload path shares the code.
6. **Tests generate every token at runtime** with `secrets.token_urlsafe(18)`. The tokens live on `self`, never in a test's local, because the test method's frame is in the traceback it inspects. The fake CLI's answers file is written into a per-test temp dir and removed. No fixture holds a token.
7. **No lab run.** No device behavior changes. The host-key and login half of `connect` is unchanged and was measured as L65 (closed). The mint half is `Workload.tokens`, which `test_real_workload.py` already runs against the real `port49` binary. No §15 row changes status.
8. **No Go change, no Ansible change.** The docs test in `tests/ci/` gains two required phrases. That is a test, not product code.

## What an operator sees at 3am

| Event | Before | After |
|---|---|---|
| An AI agent's Python script must run `show version` on `leaf1` | No library path. The docs send it to an Ansible play | `connect("leaf1", workload=w)` returns a Netmiko connection logged in under the agent's own principal |
| The same script, and the agent has no grant on `core1` | n/a | `Denied` with `.reason == "no_grants_matched"`, raised before anything connects, the same as on the Agent path |
| A script passes `agent=Workload(...)` | `AttributeError: 'Workload' object has no attribute 'token'` | `TypeError: a port49.Workload goes in workload=, not agent=`, before any mint |
| A workload script on a host with no person's agent forgets `workload=` | `NoAgent` with the CLI's words | The same `NoAgent`, ending "...passes workload=port49.Workload(...) instead" |
| An error tracker with locals capture records a failed login after the mint | The token is in a Paramiko frame's `password` local | Every frame of the chain below `connect` has no locals; file and line numbers are kept |

## Global Constraints

- Python 3.10+, standard library only (`pyproject.toml` `dependencies = []`). Match `netmiko.py`'s style: plain functions, long lines up to the file's existing width, error messages that name the remedy.
- No Go product change. snake_case for data. No reason code, warning, config key or metric is added.
- **No credential or token in logs, messages, test output or fixtures.** Tests generate tokens at runtime (Ruling 6). Never print a token while debugging a test. Assert on it instead.
- **Security rules, repeated in every implementer brief:**
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, or key files.
  - Every recursive grep excludes them. grep is ugrep: use `-e PATTERN`, never `--` before a pattern. Never grep `tests/lab/logs` or `tests/lab/captures`.
  - Never run `port49 token`, `port49 ssh`, `port49 workload token` or any real mint. The tests use `tests/fakeport49.py` and the stand-in `netmiko` in `test_netmiko.py`.
  - If a safety check refuses a command, stop and report it. Never rephrase it.
  - Edit repo files with the Edit/Write tools, never sed, perl, python or heredocs.
- **Tests:**
  - On this host `/tmp` is tmpfs. `TMPDIR` is a short private directory on ext4: `export TMPDIR=$(mktemp -d ~/.cache/p49t.XXXX) && chmod 700 $TMPDIR`.
  - Per task, run `make test-python`, plus `go test ./tests/ci/ -count=1` when docs change.
  - The final task runs `make test && make vet && make docs`. `git status --short` after `make docs` shows no diff.
  - A failure this plan does not name is reported, not fixed in passing.
- **Commits:**
  - Conventional Commits, one per task, with an explicit pathspec.
  - Every message ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and nothing else. No `Claude-Session:` line, and no claude.ai URL anywhere: commits, PR body, comments.
- **Branch:** `fix/workload-netmiko-56`, from `main` `012542a6`, in `.worktrees/workload-netmiko-56`. Tasks run in order: Task 2 builds on Task 1's `_connect` split, and Task 3 documents both.
- **Lab:** none (Ruling 7).

## Review Focus

1. **No token reaches the caller.** Check every return, attribute, closure, exception (`str`, `repr`, `args`, `vars`, `.results`) and traceback frame on both paths. The tests in Tasks 1 and 2 walk the connection's object graph and every frame of the chain. Check the walk itself skips nothing but the connection's own `password`, `secret` and the fake's `kw`.
2. **Frame clearing stops at the caller's exception.** `connect` called inside the caller's `except` block must leave that exception's frames alone (Task 1's guard test).
3. **Every refusal fails closed before ConnectHandler is built.** Covers a deny, a second factor, a device fault, a stopped run, both arguments, crossed arguments and no agent. The stand-in's `captured` stays empty.
4. **The Workload path runs the CLI once.** `fakeport49.argvs` has one entry, and the devices file holds `["leaf1"]`.
5. **Docs never offer `agent=` or `port49.Agent` to an agent.** The quick-start's three existing required phrases stay.

---

### Task 1: connect keeps the token out of every closure and traceback (Ruling 5)

**Files:**
- Modify `clients/python/src/port49/netmiko.py`: split `connect` (`:186-274`) into `connect` and `_connect`, add `_clear_frames`, and make the refresh lambda (`:247-248`) close over `address` and `username`.
- Test: `clients/python/tests/test_netmiko.py`.

**Interfaces:**
- `connect(device, *, enable=False, agent=None, ssh_config=None, **netmiko_kwargs)`: the signature is unchanged in this task.
- `_connect(device, enable, agent, ssh_config, netmiko_kwargs)`: the old body.
- `_clear_frames(exc, stop)`.

- [ ] **Step 1: Write the failing tests.**

  In `test_netmiko.py`:
  - Add `import secrets` and `import traceback` to the imports.
  - Below `NEXT_ERROR`, add:

    ```python
    AUTH_FAILS = []  # set: the next _open fails in a frame that holds the password, as Paramiko's auth does


    def _authenticate(password):
        raise Exception("Authentication to device failed.")
    ```

  - In `FakeConnection._open`, insert immediately before `EVENTS.append("authenticated")`:

    ```python
            if AUTH_FAILS:
                AUTH_FAILS.pop()
                _authenticate(self.kw["password"])
    ```

  - Below `known(...)`, add:

    ```python
    # The connection's own attributes Netmiko logs in with (and the stand-in's copy of its kwargs).
    NETMIKO_HOLDS = {"password", "secret", "kw"}


    def reaches(root, secret, skip=()):
        """Whether secret is reachable from root through attributes, containers, bound methods and closures,
        root's skip attributes aside: what a caller could read off it."""
        seen, todo = set(), [root]
        while todo:
            obj = todo.pop()
            if id(obj) in seen or isinstance(obj, (types.ModuleType, type)):
                continue
            seen.add(id(obj))
            if isinstance(obj, str):
                if secret in obj:
                    return True
                continue
            if isinstance(obj, (bytes, bytearray)):
                if secret.encode() in obj:
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
            d = getattr(obj, "__dict__", None)
            if isinstance(d, dict):
                todo += [v for k, v in d.items() if not (obj is root and k in skip)]
            for slot in getattr(type(obj), "__slots__", ()):
                todo.append(getattr(obj, slot, None))
        return False


    def frame_locals(exc):
        """repr of every local of every frame in exc's traceback and in its causes' and contexts', shown or
        suppressed."""
        out, todo, seen = [], [exc], set()
        while todo:
            e = todo.pop()
            if e is None or id(e) in seen:
                continue
            seen.add(id(e))
            tb = e.__traceback__
            while tb is not None:
                out.append(repr(tb.tb_frame.f_locals))
                tb = tb.tb_next
            todo += [e.__cause__, e.__context__]
        return "\n".join(out)
    ```

  - In `class NetmikoTest`, add:

    ```python
        def minted(self):
            """A FakeAgent with tokens made now. They live on self, never in a test's local: the test's own
            frame is in the traceback the tests read."""
            self.login, self.enable = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
            return FakeAgent(Token("leaf1", "10.0.0.11", "arista_eos", "alice", self.login, self.enable))

        def test_the_connection_holds_the_token_only_where_netmiko_logs_in_with_it(self):  # #56
            for kh in (known("ssh-ed25519 AAAA1"), known()):  # a known key, and a first contact
                conn, _ = self.connect(kh, agent=self.minted(), enable=True)
                self.assertEqual((captured["password"], captured["secret"]), (self.login, self.enable))
                for secret in (self.login, self.enable):
                    self.assertFalse(reaches(conn, secret, NETMIKO_HOLDS), kh)

        def test_a_failure_after_the_mint_leaves_no_token_in_a_traceback(self):  # #56
            AUTH_FAILS.append(True)
            with self.assertRaises(Exception) as cm:
                self.connect(known("ssh-ed25519 AAAA1"), agent=self.minted())
            e = cm.exception
            text = "".join(traceback.TracebackException.from_exception(e, capture_locals=True).format())
            for secret in (self.login, self.enable):
                self.assertNotIn(secret, text)
                self.assertNotIn(secret, frame_locals(e))
                self.assertNotIn(secret, str(e) + repr(e) + repr(e.args))
            self.assertIn("_authenticate", text)  # the frames stay, file and line; only their locals go

        def test_a_host_key_refusal_leaves_no_token_in_its_suppressed_context(self):  # #56
            NEXT_ERROR.append(BadHostKeyException("Host key for server '10.0.0.11' does not match"))
            with self.assertRaises(HostKeyError) as cm:
                self.connect(known("ssh-ed25519 AAAA1"), agent=self.minted())
            self.assertIsNotNone(cm.exception.__context__)
            self.assertNotIn(self.login, frame_locals(cm.exception))

        def test_a_callers_own_exception_keeps_its_frames(self):  # #56: the clearing stops at connect
            def caller_fails():
                mine = "kept"  # noqa: F841
                raise KeyError("the caller's own")
            try:
                caller_fails()
            except KeyError as outer:
                AUTH_FAILS.append(True)
                with self.assertRaises(Exception):
                    self.connect(known("ssh-ed25519 AAAA1"), agent=self.minted())
                self.assertEqual(outer.__traceback__.tb_next.tb_frame.f_locals.get("mine"), "kept")
    ```

  - In `test_a_failure_after_the_mint...`, `frame_locals` reads the `connect` helper's frame and the test method's frame too. Both hold only `self`, `kh`, the `FakeAgent` and the `Token`, whose `repr`s show no token (`Token.login` is `repr=False`; `FakeAgent` has the default `repr`). Do not move a token into a local.

- [ ] **Step 2: Run them and see them fail.**

  Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s clients/python/tests -p test_netmiko.py -v 2>&1 | tail -30`.

  Expected:
  - `test_the_connection_holds_the_token_only...` fails: the refresh lambda's closure holds the `Token`.
  - `test_a_failure_after_the_mint...` fails: `_authenticate`'s `password` local.
  - `test_a_host_key_refusal...` passes today: the stand-in holds no password in that frame. It stays as a guard for the suppressed context.
  - `test_a_callers_own_exception_keeps_its_frames` passes today. It guards against the fix overreaching.

  Paste the red output. Its assertion messages must not print a token: `assertFalse` and `assertNotIn` on a long text print the haystack, so if one fails, paste only the test name and the assertion line.

- [ ] **Step 3: Implement.** In `netmiko.py`:
  - Add `import traceback` to the imports.
  - Rename the current `def connect(device, *, enable=False, agent=None, ssh_config=None, **netmiko_kwargs):` to `def _connect(device, enable, agent, ssh_config, netmiko_kwargs):`. Leave the body as is, except:
    - After the `device_type` check, add `address, username = tok.address, tok.username`.
    - The `_pin(...)` call's lambda becomes:

      ```python
                  _pin(conn, kh, accepted, device, field, lambda: hostkeys.lookup(
                      device, address, port=port, username=username, ssh_config=ssh_config))
      ```

      Nothing nested in `_connect` may name `tok` (a closure would keep it).
  - Above `_connect`, add:

    ```python
    def _clear_frames(exc, stop):
        """Clear the locals of every frame in exc's traceback, and in its causes' and contexts', up to stop: the
        exception the caller was handling when it called connect, whose frames are the caller's. connect's
        frames held the token, and Paramiko's hold it as the password; a traceback printed with its locals, or
        an error tracker that records them, shows none of it. Files and line numbers stay."""
        todo, seen = [exc], set()
        while todo:
            e = todo.pop()
            if e is None or e is stop or id(e) in seen:
                continue
            seen.add(id(e))
            traceback.clear_frames(e.__traceback__)  # skips a frame still running (connect's own)
            todo += [e.__cause__, e.__context__]


    def connect(device, *, enable=False, agent=None, ssh_config=None, **netmiko_kwargs):
        """A Netmiko connection to device, logged in with a port49 token from agent (default Agent(): a
        person's). The token goes to Netmiko, as its password and secret, and nowhere else: no return value,
        closure, exception or traceback local of connect's holds it."""
        outer = sys.exc_info()[1]
        try:
            return _connect(device, enable, agent, ssh_config, netmiko_kwargs)
        except BaseException as e:
            _clear_frames(e, outer)
            raise
    ```

  - `sys` is already imported.

- [ ] **Step 4: Run** `make test-python`. Expected: all pass.

  **Mutation checks** (restore each after):
  - Put `tok.address` back in the lambda: the connection test goes red.
  - Comment out `_clear_frames(e, outer)`: the traceback test goes red.
  - Change `e is stop` to `False`: the caller's-frames test goes red.

- [ ] **Step 5: Commit.**

  `git add clients/python/src/port49/netmiko.py clients/python/tests/test_netmiko.py && git commit -m "fix(python): connect keeps the token out of its closures and every traceback it raises (#56)"`

---

### Task 2: `connect(device, workload=Workload(...))` (Rulings 1–4)

**Files:**
- Modify `clients/python/src/port49/netmiko.py`: the module docstring (`:1-6`), the imports (`:15-16`), a new `_mint`, and `connect` and `_connect` take `workload`.
- Test: `clients/python/tests/test_netmiko.py`.

**Interfaces:**
- `connect(device, *, enable=False, agent=None, workload=None, ssh_config=None, **netmiko_kwargs)`.
- `_connect(device, enable, agent, workload, ssh_config, netmiko_kwargs)`.
- `_mint(device, enable, agent, workload) -> Token`.

- [ ] **Step 1: Write the failing tests.** In `test_netmiko.py`:
  - Add `import json`.
  - Below the `sys.path.insert` line, add `sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))`.
  - After the stand-in `netmiko` is installed, add `import fakeport49 as fake  # noqa: E402`.
  - Widen the `port49` import to `from port49 import (Agent, Denied, DeviceFault, HostKeyError, MFARequired, NoAgent, Temporary, Token, Workload, hostkeys)  # noqa: E402`.
  - The `connect` helper takes `workload=None`, and its call becomes:

    ```python
            if workload is None:
                agent = agent or FakeAgent()
            conn = p49netmiko.connect(device, agent=agent, workload=workload, **kw)
    ```

  - Add at module level:

    ```python
    def permitted(login, enable=None):
        """`port49 workload token --format json`'s answer for leaf1, permitted."""
        it = {"device": "leaf1", "verdict": "permit", "address": "10.0.0.11", "platform": "arista_eos",
              "username": "svc", "login": login, "expires_at": "2026-11-09T10:00:00Z"}
        if enable:
            it["enable"] = enable
        return {"stdout": json.dumps({"principal": "spiffe://example.com/agent/ro", "results": [it], "refused": []})}


    def refused(item, code=77):
        return {"stdout": json.dumps({"principal": "spiffe://example.com/agent/ro", "results": [], "refused": [item]}),
                "code": code}
    ```

  - In `class NetmikoTest`, add:

    ```python
        def workload(self, *answers):
            self.fake_dir = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, self.fake_dir, True)  # the fake's answers hold the made-up tokens
            self.err = io.StringIO()
            return Workload("https://broker.example.com:8443", "/ca.pem", "/w.pem", "/w.key",
                            port49=fake.make(self.fake_dir, list(answers)), stderr=self.err, timeout=30)

        def made(self):
            self.login, self.enable = secrets.token_urlsafe(18), secrets.token_urlsafe(18)

        def test_a_workload_mints_once_by_workload_token_and_logs_in_with_it(self):  # #56
            self.made()
            conn, _ = self.connect(known("ssh-ed25519 AAAA1"), workload=self.workload(permitted(self.login, self.enable)),
                                   enable=True)
            argvs = fake.argvs(self.fake_dir)
            self.assertEqual(len(argvs), 1)
            self.assertEqual(argvs[0][:2], ["workload", "token"])
            self.assertIn("--enable", argvs[0])
            self.assertEqual(fake.device_files(self.fake_dir), [["leaf1"]])
            self.assertEqual((captured["host"], captured["username"], captured["password"], captured["secret"]),
                             ("10.0.0.11", "svc", self.login, self.enable))
            self.lookup.assert_called_once_with("leaf1", "10.0.0.11", port=22, username="svc", ssh_config=None)
            for secret in (self.login, self.enable):
                self.assertFalse(reaches(conn, secret, NETMIKO_HOLDS))
                self.assertNotIn(secret, self.err.getvalue())

        def test_a_workloads_failure_after_the_mint_leaves_no_token_in_a_traceback(self):  # #56
            self.made()
            AUTH_FAILS.append(True)
            with self.assertRaises(Exception) as cm:
                self.connect(known("ssh-ed25519 AAAA1"), workload=self.workload(permitted(self.login)))
            self.assertNotIn(self.login, frame_locals(cm.exception))

        def test_a_workloads_refusal_raises_what_an_agents_does_before_connecting(self):  # #56
            mfa = {"accept": ["hardware_key_touch"], "reuse_for_seconds": 900}
            for item, cls in [
                    ({"device": "leaf1", "verdict": "deny", "reason": "no_grants_matched"}, Denied),
                    ({"device": "leaf1", "verdict": "deny", "reason": "per_login_mfa_required", "per_login_mfa": mfa},
                     MFARequired),
                    ({"device": "leaf1", "error": "device_unconfigured", "detail": "fixed words"}, DeviceFault)]:
                captured.clear()
                with self.assertRaises(cls, msg=item) as cm:
                    self.connect(known("ssh-ed25519 AAAA1"), workload=self.workload(refused(item)))
                self.assertEqual((cm.exception.device, captured), ("leaf1", {}), item)
                self.assertEqual(len(fake.argvs(self.fake_dir)), 1)
            # the deny's reason, as on the Agent path
            with self.assertRaises(Denied) as cm:
                self.connect(known(), workload=self.workload(refused({"device": "leaf1", "verdict": "deny",
                                                                       "reason": "no_grants_matched"})))
            self.assertEqual(cm.exception.reason, "no_grants_matched")

        def test_a_stopped_workload_run_keeps_no_token_on_its_error(self):  # #56, Ruling 4
            self.made()
            answer = {"stdout": json.dumps({"principal": "p", "results": json.loads(permitted(self.login)["stdout"])["results"],
                                            "refused": [], "stopped": "broker_unavailable"}), "code": 75}
            captured.clear()
            with self.assertRaises(Temporary) as cm:
                self.connect(known("ssh-ed25519 AAAA1"), workload=self.workload(answer))
            self.assertEqual(cm.exception.results.tokens, {"leaf1": None})  # the name stays, the token does not
            self.assertFalse(reaches(cm.exception, self.login))
            self.assertEqual(captured, {})

        def test_agent_and_workload_together_or_crossed_are_refused_before_minting(self):  # #56, Ruling 2
            agent = FakeAgent()
            w = self.workload(permitted("unused"))
            with self.assertRaises(ValueError):
                p49netmiko.connect("leaf1", agent=agent, workload=w)
            with self.assertRaises(TypeError):
                p49netmiko.connect("leaf1", agent=w)
            with self.assertRaises(TypeError):
                p49netmiko.connect("leaf1", workload=agent)
            self.assertEqual((fake.argvs(self.fake_dir), agent.asked), ([], []))

        def test_no_agent_and_no_workload_names_workload(self):  # #56, Ruling 2
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d, True)
            none = Agent(port49=fake.make(d, [{"stdout": fake.item(device="leaf1", error="no_agent",
                                                                    detail="no agent answers: run port49 login"),
                                                "code": 1}]), stderr=io.StringIO())
            with mock.patch.object(p49netmiko, "Agent", lambda: none):
                with self.assertRaises(NoAgent) as cm:
                    p49netmiko.connect("leaf1")
            self.assertEqual(cm.exception.code, "no_agent")
            self.assertIn("workload=port49.Workload(...)", str(cm.exception))
            with self.assertRaises(NoAgent) as cm:  # an agent the caller chose: its own words only
                p49netmiko.connect("leaf1", agent=none)
            self.assertNotIn("workload=", str(cm.exception))
    ```

  - The first stopped-run assertion relies on `MintResults.without_tokens()` (`client.py:69-71`).

- [ ] **Step 2: Run them and see them fail.**

  Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s clients/python/tests -p test_netmiko.py -v 2>&1 | tail -40`.

  Expected:
  - Every new test fails with `TypeError: connect() got an unexpected keyword argument 'workload'`, except two.
  - `test_no_agent_and_no_workload...` fails on the missing `workload=port49.Workload(...)`.
  - `p49netmiko.connect("leaf1", agent=w)` raises `AttributeError`, not `TypeError`.

  Paste the red output (test names and assertion lines only, Task 1 Step 2's rule).

- [ ] **Step 3: Implement.** In `netmiko.py`:
  - The module docstring becomes:

    ```python
    """Netmiko through port49 (design §17; decision 46 rulings 13 and 16; #56).

    The token comes from a Workload through `port49 workload token` (connect's workload=, a machine's own
    identity), or from your agent through `port49 token --json` (agent=, by default a person's). The device's key
    is OpenSSH's known_hosts entry under its inventory name: the only key accepted once filed, and filed at first
    contact, before authentication, unless revoked. The token goes to Netmiko and nowhere else, and is never
    printed."""
    ```

  - The imports become:

    ```python
    from .client import Agent, Workload
    from .errors import DeviceFault, HostKeyError, NoAgent, Port49Error
    ```

  - Above `_clear_frames`, add:

    ```python
    def _mint(device, enable, agent, workload):
        """The Token connect logs in with: one `port49 workload token` run for device when workload is given
        (never rerun, decision 46 ruling 11), else agent's `port49 token` (default Agent(), a person's). A
        Workload's refusal raises what Agent.token raises for it; a stopped run's error keeps its device names and
        refusals and drops its tokens."""
        if workload is None:
            try:
                return (agent or Agent()).token(device, enable=enable)
            except NoAgent as e:
                if agent is not None:
                    raise
                raise NoAgent(e.code, f"{e.detail or e.code}; a program with a machine identity of its own passes "
                              f"workload=port49.Workload(...) instead", device) from None
        try:
            res = workload.tokens([device], enable=enable)
        except Port49Error as e:
            if getattr(e, "results", None) is not None:
                e.results = e.results.without_tokens()
            raise
        tok = res.tokens.get(device)
        if tok is not None:
            return tok
        refusal = res.refused.get(device)
        if refusal is not None:
            raise refusal.exception()
        raise DeviceFault("no_token", "port49 workload token answered nothing for this device", device)
    ```

  - `_connect` becomes `def _connect(device, enable, agent, workload, ssh_config, netmiko_kwargs):`. After the `owned` check and before the `valid_name` check, insert:

    ```python
        if agent is not None and workload is not None:
            raise ValueError("port49.netmiko.connect takes agent= (a person's) or workload= (a machine's), not both")
        if isinstance(agent, Workload):
            raise TypeError("a port49.Workload goes in workload=, not agent=")
        if workload is not None and not isinstance(workload, Workload):
            raise TypeError("workload= takes a port49.Workload; a person's Agent goes in agent=")
    ```

  - The mint line becomes `tok = _mint(device, enable, agent, workload)`.
  - `connect` becomes:

    ```python
    def connect(device, *, enable=False, agent=None, workload=None, ssh_config=None, **netmiko_kwargs):
        """A Netmiko connection to device, logged in with a port49 token: a Workload's (workload=, a machine's own
        identity) or an Agent's (agent=, default Agent(): a person's), never both. The token goes to Netmiko, as its
        password and secret, and nowhere else: no return value, closure, exception or traceback local of
        connect's holds it."""
        outer = sys.exc_info()[1]
        try:
            return _connect(device, enable, agent, workload, ssh_config, netmiko_kwargs)
        except BaseException as e:
            _clear_frames(e, outer)
            raise
    ```

- [ ] **Step 4: Run** `make test-python`. Expected: all pass, the Ansible unit suite included, with no change there.

  **Mutation checks** (restore each after):
  - Drop the `.results` scrub: the stopped-run test goes red.
  - Drop the `isinstance(agent, Workload)` check: the crossed test goes red, with `AttributeError`.
  - Drop the `NoAgent` re-raise: the no-agent test goes red.
  - Make `_mint` return `res.tokens[device]` with no refused branch: the refusal test goes red, with `KeyError`.

- [ ] **Step 5: Commit.**

  `git add clients/python/src/port49/netmiko.py clients/python/tests/test_netmiko.py && git commit -m "feat(python): port49.netmiko.connect takes a Workload, so a machine identity has a device path (#56)"`

---

### Task 3: the docs give a Python workload its device path

**Files:**
- Modify `tests/ci/docs_content_22_test.go:14-18`: two required phrases.
- Modify `docs/site/agents/quick-start.md`: `:23-31` (rule 3), `:85-87`, `:189-190`, a new `### 4b` after `:291`, and `:301-309`.
- Modify `docs/site/agents/setup-runbook.md:101-114` (step 8).
- Modify `clients/python/README.md`: `## Netmiko and host keys` (`:108-114`) and `## Secrets` (`:169-174`). It is included in `docs/site/operate/install/clients.md:61`.
- Modify `docs/design/2026-08-23-policy-engine-spec.md:10190` (decision 46 ruling 16) and `docs/design/2026-08-21-port49-design.md:2442` (the client table).

- [ ] **Step 1: Write the failing check.** In `docs_content_22_test.go`, add two phrases to the quick-start's list, after `"never eAPI",`:

  ```go
  		"connect(\"leaf1\", workload=workload)", "never call `connect` without `workload=`",
  ```

  Run `go test ./tests/ci/ -count=1 -run 'Docs|Must' 2>&1 | tail -20`. If that pattern matches nothing, run `go test ./tests/ci/ -count=1 2>&1 | tail -20`. Expected: the two new phrases are reported missing from `agents/quick-start.md`. Paste the red output.

- [ ] **Step 2: quick-start.md.**
  - **Rule 3 (`:23-31`).** Keep the line breaks exactly as below, so that each required phrase sits on one line:

    ```markdown
    3. **The tooling mints and presents the token. The token never enters the agent's context.** Use the Ansible
       lookup, which reads the token from the `port49` command and hands it to the connection and nowhere else, or
       the Python library's `port49.netmiko.connect` with a `port49.Workload`, which mints with the agent's own
       certificate and hands the token to the Netmiko connection and nowhere else ([step 4b](#4b-or-run-it-from-python)).
       Never use `port49.Agent`, and never call `connect` without `workload=`: both use a person's session. Never run
       `port49 token`, `port49 workload token` or `port49 ssh` in a shell: on success they print the token (and
    ```

    Then the rest of the rule from "`port49 token --json` the broker's whole answer" on, unchanged.
  - **`:85-87`** becomes:

    "`port49.Workload` presents the agent's own certificate. `port49.Agent` presents whatever person logged in on the machine, so an agent never constructs one. Never print `res` or `res.tokens`, and never take a token out of them for a connection of the agent's own: to run a command, use `connect` ([step 4b](#4b-or-run-it-from-python)), which mints for itself."
  - **`:189-190`** becomes:

    "The agent connects over SSH only: Ansible `network_cli` or Netmiko through `port49.netmiko.connect`, never eAPI, `httpapi` or NETCONF. If a play or a script would use another transport, stop and ask a human."
  - **New section after `:291`, before `### 5. What is recorded`:**

    ````markdown
    ### 4b. Or run it from Python

    `port49.netmiko.connect` with `workload=` mints through `port49 workload token` with the agent's certificate,
    checks the device's host key under its inventory name before the token is sent
    ([Install the clients](../operate/install/clients.md#netmiko-and-host-keys)), and returns a Netmiko
    connection. The token is in no return value, exception or traceback.

    ```python
    import port49
    from port49.netmiko import connect

    workload = port49.Workload(broker="https://broker.example.com:8443", broker_ca="/etc/port49/ca.pem",
                               cert="/etc/port49/agent-cert.pem", key="/etc/port49/agent-key.pem")
    try:
        conn = connect("leaf1", workload=workload)
    except port49.Port49Error as e:
        print(e.device, e.code)   # a code, never a token
        raise SystemExit(1)
    try:
        print(conn.send_command("show version"))   # the command's output, and only that
    finally:
        conn.disconnect()
    ```

    A refusal raises before anything connects: `Denied`, whose `.code` and `.reason` are the reason code, or
    `MFARequired` for a device that asks for a person's second factor ([above](#per_login_mfa_required-devices-stay-human)).
    Report the code and stop. Netmiko keeps the token on the connection as `password` (and `secret` with
    `enable=True`) to log in again, so never print `conn`, `vars(conn)` or either attribute. Never call
    `connect` without `workload=`: with none it uses a person's agent (rule 1), and with no person's agent it
    raises `NoAgent`. Each `connect` runs `port49 workload token` once for its one device and never again.
    ````

    Check the two new required phrases. `connect("leaf1", workload=workload)` is in the code block. "never call `connect` without `workload=`" is in rule 3. Both are case-sensitive, and the section's "Never call" capital does not count.
  - **`:301-309`:** add a bullet after the first:

    "- Never constructs `port49.Agent`, and never calls `port49.netmiko.connect` without `workload=`."

- [ ] **Step 3: setup-runbook.md, step 8 (`:101-114`).**
  - The paragraph at `:103-107` becomes:

    "Run the one `show` command of [the quick start's worked example](quick-start.md#the-worked-example-one-read-only-agent) over SSH: through the Ansible lookup over `network_cli`, with `no_log: true` on the mint and on the command task, or through `port49.netmiko.connect` with the agent's `port49.Workload` ([step 4b](quick-start.md#4b-or-run-it-from-python)). Never construct `port49.Agent`, and never call `connect` without `workload=`: either uses a person's session."
  - In the **Check:** paragraph, "the play's `debug` of `out.stdout_lines` prints the command's output (the example registers the result and prints that one key; ...)" becomes "the play's `debug` of `out.stdout_lines`, or the script's print of `send_command`'s output, prints the command's output (the play registers the result and prints that one key; the tasks that hold the token stay censored, and the agent never prints the fact, `ansible_password` or the connection's `password`)". The rest of the paragraph is unchanged.
  - Add no fenced block (the runbook's limit is 5 lines, `docs_content_22_test.go:54`).

- [ ] **Step 4: clients/python/README.md.**
  - In `## Netmiko and host keys`, the code block becomes:

    ```python
    from port49 import Workload
    from port49.netmiko import connect

    conn = connect("leaf1", enable=True)    # a person's token, through the agent `port49 login` started
    w = Workload(broker="https://broker.example.com:8443", broker_ca="/etc/port49/ca.pem",
                 cert="/etc/port49/w.pem", key="/etc/port49/w.key")
    conn = connect("leaf1", workload=w)     # a machine's token, through `port49 workload token`
    # a Netmiko connection either way; extra keyword arguments pass to Netmiko
    ```

  - Directly after it, before "port49 stores no host key.", add:

    "- `workload=` runs `port49 workload token` once for the one device, and never again (a workload run is never rerun). A refusal raises what the agent path raises: `Denied`, `MFARequired` (a device that asks for a second factor the run did not prove), `DeviceFault`. A stopped run raises its code's class, and its `.results` names the device and holds no token.
    - `agent=` and `workload=` together are a `ValueError`. A `Workload` as `agent=`, or anything but a `Workload` as `workload=`, is a `TypeError`. All three are raised before anything is minted. With neither, `connect` uses `Agent()`, and with no agent running raises `NoAgent`, naming `workload=`.
    - Host keys are the same on both paths, below."
  - In `## Secrets`, after "It is read from the CLI's stdout and handed to Netmiko (or Ansible) only.", add: "`connect`'s connection holds it only as Netmiko's `password` and `secret`, which Netmiko logs in again with. An exception `connect` raises has no locals left in the frames of its traceback, or of the tracebacks it chains, below `connect`, so a traceback printed with its locals shows no token."
- [ ] **Step 5: The spec and the design.**
  - Spec decision 46 ruling 16 (`:10190`) becomes:

    "- **16. The Netmiko example** is `port49.netmiko.connect`. *As built (#56, 2026-11-09):* `connect(device, workload=Workload(...))` mints through one `port49 workload token` run for the device, and a refusal raises the Agent path's class. `agent=` and `workload=` together, or crossed, are refused before any mint, and with neither it is `Agent()`. The token reaches Netmiko only: `connect` clears the locals of every frame of a traceback it raises, up to the caller's own exception."
  - Design client table (`:2442`): "identity, mint, sweep, retry over the CLI; Netmiko connect (`clients/python`, plan 9d)" becomes "identity, mint, sweep, retry over the CLI; Netmiko connect for an Agent or a Workload (`clients/python`, plan 9d; #56)".
- [ ] **Step 6: The grep.** Run `grep -rn --exclude=realm.json --exclude='*.env' --exclude='*-key.pem' --exclude='*.keytab' -e 'only mints' -e 'ships no connector' -e 'runs no device command' -e 'Use the Ansible play here' docs/site clients`. It must find nothing.
- [ ] **Step 7: Run** `go test ./tests/ci/ -count=1 && make docs && git status --short`. Expected:
  - PASS.
  - `make docs` (MkDocs strict) resolves `#4b-or-run-it-from-python` and `clients.md#netmiko-and-host-keys`. If MkDocs slugs either differently, use the anchor it reports, in every place that links it.
  - No generated diff.
- [ ] **Step 8: Commit.**

  `git add tests/ci/docs_content_22_test.go docs/site/agents/quick-start.md docs/site/agents/setup-runbook.md clients/python/README.md docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md && git commit -m "docs: an agent runs device commands from Python through connect with its Workload, never a person's Agent (#56)"`

---

### Task 4: Final verification

- [ ] Under the Global Constraints TMPDIR, run `make test && make vet && make docs && git status --short`, and paste the summary lines. A failure this plan does not name is reported, not fixed in passing.
- [ ] Run Task 3 Step 6's grep again.
- [ ] Run `grep -rn --exclude=realm.json --exclude='*.env' --exclude='*-key.pem' --exclude='*.keytab' -e 'tok\.' clients/python/src/port49/netmiko.py`. Every hit must be in `_connect`'s own body, never inside a `lambda` or nested `def`.

## Operator-facing notes for the PR body

- **Python client: a machine identity can run device commands.** `port49.netmiko.connect("leaf1", workload=port49.Workload(...))` mints with the workload's certificate through one `port49 workload token` run, checks the host key as before, and returns a Netmiko connection. Use it for an automation job or an AI agent with its own identity instead of an Ansible play, if Python suits better.
- **Refusals look the same on both paths.** A deny is `Denied` (`.reason`), a second factor is `MFARequired`, and a broker fault is `DeviceFault`, all raised before anything connects. A stopped run raises its code's class with no token on `.results`.
- **Mistakes fail closed before any mint.** `agent=` with `workload=` is a `ValueError`. `agent=Workload(...)` is a `TypeError` (it was an `AttributeError`). With neither and no agent running, `NoAgent` now names `workload=`.
- **No token in tracebacks, on either path.** Before, a login that failed after the mint left the token in a Paramiko frame's `password` local, and the returned connection's host-key refresh kept the whole token object. An error tracker that records locals could store it. `connect` now clears those frames' locals (file and line numbers stay) and keeps no token beyond Netmiko's own `password` and `secret`, and the log filter Netmiko holds them in until `disconnect()` (call it, or use the connection as a context manager, when done). A traceback raised inside your own `except` block keeps your frames.
- **AI agent docs:** the quick start and the setup runbook now allow `port49.netmiko.connect` with a `Workload` (new step 4b), and still forbid `port49.Agent`, and `connect` without `workload=`.
- No server, CLI, Ansible or config change. No lab run.

## Left for later

- **`purpose=` on `connect`.** `port49 workload token --purpose` puts it in the mint record (`cmd/port49/workload.go:159`). `connect` passes none. Adding it is a keyword passed to `Workload.tokens`, refused with `agent=`, which has no such flag.
- **Many devices from one workload run.** Each `connect` is one run for one device. A fleet script connecting to hundreds of devices runs the CLI that many times. A form that takes a sweep's result would hand tokens to the caller, so it needs its own design.
