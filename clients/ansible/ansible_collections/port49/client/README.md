# port49.client

Device tokens from port49 for Ansible: the lookup `port49.client.token`. It drives the `port49`
CLI through the port49 Python library (`clients/python`), so a hardware key, its PIN, a touch and
`per_login_mfa` take the one path they take at a terminal.

## Install

```
pip install ./clients/python                                   # on the controller: the library
ansible-galaxy collection install ./clients/ansible/ansible_collections/port49/client
```

Install the library from the tree, not by name from PyPI: the name is not the project's. Where
ansible-core lives in a pipx venv, `pipx inject ansible-core ./clients/python`.

`port49` must be on the controller's `PATH` (or pass `port49=/opt/port49/bin/port49`), and
`port49 login` must have started an agent. Needs ansible-core 2.16 or later.

## Use: mint once per host per play

```yaml
- hosts: leaves
  gather_facts: false
  pre_tasks:
    - name: mint this host's token
      ansible.builtin.set_fact:
        port49: "{{ lookup('port49.client.token', inventory_hostname, field='all', enable=true) }}"
      no_log: true
  vars:
    ansible_connection: ansible.netcommon.network_cli
    ansible_network_os: arista.eos.eos
    ansible_user: "{{ port49.username }}"
    ansible_password: "{{ port49.login }}"
    ansible_become_password: "{{ port49.enable }}"
  tasks:
    - arista.eos.eos_facts:
```

`inventory_hostname` must be the name port49's inventory knows. A token is single-use and short
lived; each call of the lookup is a mint.

- **Never put the lookup itself in `ansible_password`.** Ansible templates a connection variable at
  every task, so the lookup would mint at each one (lab entry L66 (a) is to measure how many
  logins a play makes). Mint in a `set_fact` and point `ansible_password` at the fact.
- **Never `cacheable: true` on the mint.** It writes the token to the fact-cache backend (a
  jsonfile, or Redis in a real deployment).
- **A reconnect needs a new mint.** The token is single-use for a login. `network_cli` closes an
  idle persistent connection (`persistent_connect_timeout`, 30 s by default), and
  `meta: reset_connection` or a reboot closes it too; the next task would log in again with the
  spent token and fail with an authentication error that points nowhere near port49. Mint again
  (a second `set_fact`) before a long gap. Unmeasured; L66 (b) is to measure a play with an idle gap.
- **`no_log: true` on the mint.** The fact holds the token. With `no_log`, `-v`, `-vvv` and
  `-vvvvv` print `censored` for the task and nothing else (the collection's real-ansible test
  runs all four and searches the output for the token).
- **A play longer than `receipt_max_age`** needs a new mint: the token is single-use and expires,
  so a long play re-mints (a second `set_fact`) rather than reusing one. Keep each mint close to
  the work that uses it.
- **A device that asks for `hardware_key_touch`** wants a touch per mint, and forks mint at once.
  Run `port49 token <one such device>` before the play, so the agent's `reuse_for` covers the forks.
- **`field`** is `login` (the default), `enable` (needs `enable=true`), `username`, `address`,
  `platform` or `all`, a dict of those plus `expires_at`.

### A machine: workload mode

Give all of `broker`, `broker_ca`, `cert` and `key` and the lookup drives `port49 workload token`
instead of your agent. It reads the certificate and key at every run.

```yaml
lookup('port49.client.token', inventory_hostname, field='all',
       broker='https://broker.example.com:8443', broker_ca='/etc/port49/ca.pem',
       cert='/etc/port49/w.pem', key='/etc/port49/w.key')
```

`touch_key` (a `pkcs11:` reference with a `pin-source`) and `deadline` (seconds) reach the CLI's
flags of those names. A workload run is never rerun by the library or the lookup, even when the
broker was unreachable: the page in flight may already be minted. Running the play again is yours
to decide.

## Errors

A failed lookup raises an Ansible error that names the device and port49's code, for example
`port49: leaf2: deny no_grants_matched: no grant`. It never carries a token or the CLI's output.
A deny, a second factor the lookup cannot give (run `port49 token DEVICE` at a terminal first) or a
device the broker cannot decide fails **that host only**; the play goes on for the others. The
message always ends in port49's code, in brackets when the detail does not already hold it
(`port49: leaf2: the device has no platform [device_unconfigured]`). The lookup also raises the
message as an Ansible warning, because ansible-core 2.16 to 2.18 censor the message of a failed
`no_log` task and show only `censored`; on those versions the code appears in the
`[WARNING]` line beside it (measured on 2.16, 2.17 and 2.18; 2.19 and later print the error
itself, measured to 2.21). A workload option given without the other three, or given empty (an
unset variable), is an error: the lookup never falls back to your agent. The
lookup retries nothing beyond what the library does for an agent (a revocation sweep or a broker
outage, three tries); a deny, a locked key and a lost session are never retried. The library's
README lists the codes and what to do for each.

## Secrets

The token travels from the CLI's stdout to the lookup's return value and nowhere else: not argv,
not the environment, not a log, not an exception. The lookup prints nothing. What Ansible does with
the value is its own: it is in the task result of the `set_fact` (censored by `no_log`) and in any
later task that templates it. A `debug` of the fact, or a task without `no_log` that receives
`ansible_password`, prints or logs it at its own verbosity; keep `no_log` on those. Ansible has no
way to mark one value secret, so `no_log` on every task that templates the token is the control.

## Host keys

Everything in this section is provisional on lab entry L66; Task 12 completes it from the
measurements.

port49 stores no host key. Ansible keeps them its own way, and the two ways differ.

- **The connection keys a host by `ansible_host`, the address in Ansible's inventory, not by the
  port49 name.** `network_cli` does this on any ssh type. So an address added to a device in the
  source of truth (a dynamic inventory built from it, the usual case) is a first contact for
  Ansible, and under `host_key_auto_add` a host at that address is accepted and given the token.
  Design section 17's attack is open on this path, as it is not for `port49 ssh`. What flags it:
  the sync diff's address-change security event (spec section 10). Whether the collection closes
  the gap itself (for the Paramiko path) is undecided and waits on L66 (e).
- **Where the connection runs OpenSSH** (`ansible.builtin.ssh`), set

  ```yaml
  ansible_ssh_extra_args: "-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new"
  ```

  which files keys under the port49 name, as `port49 ssh` and the Python client do (the name is
  lowercased, as they lowercase it), and is expected to close the gap there. Without
  `accept-new`, a first contact is `Host key verification failed.` (measured against a local
  sshd: with the alias and accept-new, keys filed under the name and a changed key refused).
  **Do not set `host_key_checking = False`**: Ansible then passes `StrictHostKeyChecking=no`
  ahead of your extra args, which overrides `accept-new`. OpenSSH still withholds a password from
  a host whose key changed, but a first contact is accepted unchecked. One caveat, unmeasured
  (L66 (e)): `ansible.builtin.ssh` keys its ControlPath on address, port and user, so a second
  inventory name at an address with an open master reuses the master and its alias is never checked.
- **Never set `host_key_auto_add` with `ansible_network_cli_ssh_type: paramiko`.** Its close
  rewrites `~/.ssh/known_hosts` from Paramiko's parse, which drops `@revoked` and
  `@cert-authority` lines and comments, and so silently weakens every later `port49 ssh` and Python
  login. Use the path that leaves the file intact (`libssh`, which appends).
- **A re-keyed device has two entries**: the name (`port49 ssh`, Python, `ansible.builtin.ssh` with
  the alias) and the address (`network_cli`). Remove both with `ssh-keygen -R`:

  ```
  ssh-keygen -R leaf1
  ssh-keygen -R 10.0.0.11
  ```

## Tests

```
make test-python                               # stdlib unittest; Ansible is stubbed, none needed
PORT49_TEST_ANSIBLE_PLAYBOOK=/path/to/venv/bin/ansible-playbook make test-python   # and real ansible-core
```
