# Netmiko through port49

```
pip install './clients/python[netmiko]'
port49 login
python3 show_version.py leaf1
```

`port49.netmiko.connect("leaf1")` logs in to `leaf1` with a fresh token from your agent, as the
username the broker says, at the address inventory gives. It returns Netmiko's connection;
`show_version.py` is the whole example.

## Host keys

port49 stores no host key. The device's key is an entry in your OpenSSH `known_hosts`, filed under
the device's inventory name, the same entry `port49 ssh` files and reads:

- **First contact:** the key the device presents is filed (accept-new) before the token is sent,
  so a first connection needs nothing typed. Two scripts reaching a new device at once both
  connect, and the file holds whole lines.
- **A key already filed:** it is the only key accepted. A changed key, or a key of another type
  than the one filed, is refused before the token is sent, with the `ssh-keygen -R` command that
  removes the old entry.
- **Your ssh_config applies:** the client reads it with `ssh -G`. Your `HostKeyAlias`,
  `HashKnownHosts`, `UserKnownHostsFile`, `GlobalKnownHostsFile`, `RevokedHostKeys` and
  `StrictHostKeyChecking yes` are honoured.
- **Refused, with the setting named:** a `KnownHostsCommand` (use `port49 ssh`), a
  `UserKnownHostsFile` that keeps no key (`/dev/null`, `none`, an unwritable file), a revoked key
  (an `@revoked` line or `RevokedHostKeys`), and a host covered only by `@cert-authority`, which
  Paramiko cannot check. A refusal after the mint leaves that token unused; it expires.

See [clients/python/README.md](../../clients/python/README.md) for the full list.

Public-key authentication and the SSH agent are off, since a refused key counts against the
device's login-attempt limit (policy engine spec §15, L51).

Unlike `port49 ssh`, which presents the token once and ends the connection rather than answer a
second prompt, Netmiko's Paramiko may present the token a second time: after the device refuses
it by `password`, Paramiko can try `keyboard-interactive` with the same token. That is not
measured; a refused token is refused again, one more refused attempt against the device's limits.

The claim that Paramiko refuses a wrong key before authentication is provisional on lab entry L65.
