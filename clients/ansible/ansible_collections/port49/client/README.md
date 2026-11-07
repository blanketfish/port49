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
    ansible_user: "{{ port49.username | default(omit) }}"
    ansible_password: "{{ port49.login | default(omit) }}"
    ansible_become_password: "{{ port49.enable | default(omit) }}"
    ansible_look_for_keys: false
  tasks:
    - arista.eos.eos_facts:
```

`inventory_hostname` must be the name port49's inventory knows. A token is single-use and short
lived; each call of the lookup is a mint.

- **Keep `| default(omit)` on the connection variables**, in the play's `vars` or in inventory.
  Under `network_cli`, ansible-core templates all three for every task, the mint's `set_fact`
  included, before the fact exists; without the default the mint itself fails with
  `Error processing keyword 'remote_user': 'port49' is undefined` (or `'password'`,
  `'become_pass'`; measured on 2.21.4, and the collection's real-ansible test runs this play). The `omit` lasts only until the `set_fact`: a
  host whose mint fails stops there, so no task connects without the token.
- **Keep `gather_facts: false`, and make the mint the first `pre_tasks` entry.** Anything that
  connects before the mint connects without the token: fact gathering would log in as you, with
  your own credentials. **`ansible_look_for_keys: false`** stops `network_cli` offering your own
  ssh keys ahead of the token.
- **Never put the lookup itself in `ansible_password`.** Ansible templates connection variables
  many times per task. Measured on EOS, NX-OS, IOS-XE, vJunos-router and vSRX (L66 (a),
  `tests/lab/results/L66-<platform>.md`): with the lookup in `ansible_password` and `ansible_user`,
  a ten-task play minted 10 tokens for its first 2 tasks. The ninth unspent token was refused
  `candidate_cap_reached` (port49's `token.candidate_cap`, 8 by default), and the play failed at
  task 2. Mint once in a `set_fact` and point `ansible_password` at the fact: the same play then
  minted once and logged in once for all ten tasks.
- **Never `cacheable: true` on the mint.** It writes the token to the fact-cache backend (a
  jsonfile, or Redis in a real deployment).
- **A reconnect reuses the spent token, and that works only inside the receipt's window.**
  `network_cli` closes an idle persistent connection (`persistent_connect_timeout`, 30 s by
  default), and `meta: reset_connection` closes it too. The next task logs in again with the same
  token. Measured on all five lab platforms (L66 (b2)): both an idle gap and a `reset_connection` led to a
  second login, which port49 answered PASS `receipt_replayed` from the stored decision. That holds
  within `receipt_idle_ttl` (15 m by default) of the last use and `receipt_max_age` (2 h) of the
  first. Past either, the login fails `token_spent`, and the device reports an authentication
  error that points nowhere near port49. Mint again (a second `set_fact`) before a gap that long.
- **Never enable `persistent_log_messages`** (`ANSIBLE_PERSISTENT_LOG_MESSAGES`). The persistent
  socket carries the connection's options, password included, to the connection process, and
  with this setting the log file records them. Measured on all five lab platforms (L66 (d)): the token is
  in that log in the clear. Ansible prints a warning saying so; believe it. `-vvv` and `-vvvv`
  output held no token.
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
lookup retries nothing beyond what the library does for an agent (a revocation sweep or a
changed connection, three tries); a broker outage, a deny, a locked key and a lost session are
never retried. The library's
README lists the codes and what to do for each.

## Secrets

The token travels from the CLI's stdout to the lookup's return value and nowhere else: not argv,
not the environment, not a log, not an exception. The lookup prints nothing. What Ansible does with
the value is its own: it is in the task result of the `set_fact` (censored by `no_log`) and in any
later task that templates it. A `debug` of the fact, or a task without `no_log` that receives
`ansible_password`, prints or logs it at its own verbosity; keep `no_log` on those. Ansible has no
way to mark one value secret, so `no_log` on every task that templates the token is the control.

## Host keys

port49 stores no host key. Ansible keeps them its own way. What follows was measured with
ansible-core 2.21.4, ansible.netcommon 8.7.1, ansible-pylibssh 1.4.0 (libssh 0.12.0) and
paramiko 5.0.0. Each platform gave the same reading: EOS, NX-OS, IOS-XE, vJunos-router and vSRX (lab entry
L66, `tests/lab/results/L66-<platform>.md`). It is the client's behaviour, not the device's.

- **`network_cli` keys a host by `ansible_host`, the address in Ansible's inventory, not by the
  port49 name.** Both ssh types filed the first contact under the address.
  `ansible_libssh_config_file` naming an ssh_config with `HostKeyAlias` is not honoured: the key
  still went under the address. So an address changed for a device in the source of truth (a
  dynamic inventory built from it, the usual case) is a first contact for Ansible. Measured
  (L66 (e)): with `host_key_auto_add`, both `libssh` and `paramiko` connected to another host at
  the new address and presented it the token.
- **The lookup closes that gap before it mints.** *Measured on L66 (e3), 2026-10-16 (`tests/lab/results/L66-arista_eos.md`): with a different key already filed under the new address, it refused for both `libssh` and `paramiko` before any mint. At a new address with no entry it copies the device's key there, and `libssh` with `host_key_auto_add` still accepted the other host's key and presented the token (`paramiko` refused), so do not enable `host_key_auto_add` with `ssh_type: libssh`. Measured also without `host_key_auto_add` (L66 (e3d)): the lookup copies the name's key to a new address, the play logs in at the device's own address, and both `libssh` and `paramiko` refuse another host's key at a moved address without presenting the token. **With the lookup, run `network_cli` without `host_key_auto_add`, for either ssh type.** Only a device's very first contact (case 4 below) needs its key filed some other way: connect once with `port49 ssh`, or file a key from `ssh-keyscan` after checking it on the console.* For a
  device on `network_cli` (`ansible_connection` is `network_cli` or `ansible.netcommon.network_cli`,
  or none is visible and `ansible_network_os` is set), it compares the keys filed under the port49
  name with the keys filed under the address in `~/.ssh/known_hosts`. The address is
  `ansible_host`, else the inventory name, and `[address]:port` when `ansible_port` is not 22.
  - Name has keys, address has none: it files them under the address, then mints.
  - Both have keys, and a key type in both differs: it mints nothing and fails with
    `host_key_changed`. The message gives both fingerprints and the command that clears the stale
    address, for example `ssh-keygen -R '[10.0.0.9]:2222' -f /home/<user>/.ssh/known_hosts`. Check
    the device's key on its console first. Run the command only if the address now belongs to this device.
  - Name has none, address has keys: it copies them under the name, then mints. If no user
    known_hosts file is writable, it warns and mints anyway.
  - Neither has a key: a first contact, as before.
  - A key of the address that `@revoked` or `RevokedHostKeys` revokes fails with `host_key_revoked`.
  - `known_hosts_file` is the file to check, if `ansible_ssh_common_args` or the ssh type points
    Ansible elsewhere. It defaults to `~/.ssh/known_hosts`.
  - In workload mode every device is checked before the one mint.
  - A device not on `network_cli` is not checked. Use the `HostKeyAlias` setting below there.
    For a device other than the current host, only its own `hostvars` count: a `localhost` play's
    `ansible_connection: local` does not turn off the check for it. For the current host, its inventory
    `ansible_connection` and its play's `vars:` both count, and either one naming `network_cli` runs the
    check: an inventory `ssh` under a play's `network_cli` is checked, as Ansible connects with `network_cli`.
    An `ansible_connection` that reaches the lookup still templated (`"{{ conn }}"`) counts as `network_cli`.
  - A port49 name that is not a host in Ansible's inventory (an inventory name `l66a` minting
    `lookup('port49.client.token', p49_name)` for `srx1`) has no address the lookup can check. Minted
    on a host that connects with `network_cli`, it fails with `host_key_uncheckable` and mints nothing:
    name the inventory host by its port49 name and mint for `inventory_hostname`, as the play above does.
    On any other connection it mints, unchecked, as for any device not on `network_cli`.
  - If your ssh_config gives the device a `HostKeyAlias`, the keys filed under the alias count as the
    name's. A key type where the name and the alias disagree fails with `host_key_changed`. A
    `KnownHostsCommand` fails with `host_key_uncheckable`: the lookup cannot run it as ssh does.
  - The port is `ansible_port`, else `ansible_ssh_port`.
  - The check runs before the connection. It cannot see a key that changes later, and libssh
    accepts one (next bullet).
- **Never set `host_key_auto_add` with `ansible_network_cli_ssh_type: libssh`.** libssh appended
  the first contact and kept the file's comments and `@revoked` and `@cert-authority` lines. But
  given a changed key for a host it knew, **it accepted the new key, logged in and presented the
  token** (L66 (c), (e3b)). Without `host_key_auto_add`, and with the lookup's copy of the name's key at the address, libssh refused another host's key and presented nothing (L66 (e3d)).
- **`paramiko` with `host_key_auto_add` refused a changed key before authentication.** No TACACS+
  exchange happened and the token was never presented. It has two costs:
  - **It refuses a known_hosts file that holds an `@revoked` or `@cert-authority` line**
    (`InvalidHostKey`), so the play fails before connecting. That fails loudly and closed, but it
    means `port49 ssh`'s revocation lines and Paramiko cannot share a file.
  - **On a first contact it rewrites the file** and drops every comment.

  Of the two `network_cli` paths, this is the one that refuses a changed key. A first contact is
  still accepted. With the lookup (below), an address changed in the inventory is not a first
  contact when the device's name holds a key: the lookup copies the name's key to the new address
  first, so `paramiko` meets a changed key and refuses it (L66 (e3b), (e3d)). It stays a first
  contact for a device whose name holds no key.
- **Where the connection runs OpenSSH** (`ansible.builtin.ssh`), set

  ```yaml
  ansible_ssh_extra_args: "-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new"
  ```

  This files keys under the port49 name, as `port49 ssh` and the Python client do (the name is
  lowercased, as they lowercase it). Measured (L66 (e)): with the alias, an address moved to
  another host was refused, and the token was never presented to it. This is the measured path that
  closes the gap. Without `accept-new`, a first contact is `Host key verification failed.`
  **Do not set `host_key_checking = False`**: Ansible then passes `StrictHostKeyChecking=no`
  ahead of your extra args, which overrides `accept-new`. OpenSSH still withholds a password from
  a host whose key changed, but a first contact is accepted unchecked.
  - **One inventory name per address.** `ansible.builtin.ssh` keys its ControlPath on address,
    port and user. Measured (L66 (e2)): a second inventory name at the same address reused the
    first name's open master, and its own `HostKeyAlias` was never looked up.
  - **For `raw` against Junos, also set `ansible_ssh_use_tty: false`.** The plugin runs `raw`
    with `ssh -tt`. The Junos CLI ran the command at once, then held the session open until the
    play was killed.
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

The real-ansible run includes the play above under `network_cli`, against a closed local port; it
needs `ansible.netcommon` and `arista.eos` (in that venv, or on a collections path named by
`PORT49_TEST_ANSIBLE_COLLECTIONS`) and is skipped without them.
