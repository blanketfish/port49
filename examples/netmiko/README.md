# Netmiko through port49

`port49_netmiko.connect("leaf1")` logs in to `leaf1` with a fresh token from your agent
(`port49 login` first), as the username the broker says, at the address inventory gives.

Pin the device's key once, with `port49 devices trust leaf1`, comparing the key with the device's
console: NX-OS prints a SHA256 fingerprint; EOS, IOS-XE, vJunos-router and vSRX print the key itself
(tests/lab/results/L53-*.md), so give `--fingerprint` the `ssh-keygen -lf` of that key. The example refuses a device with no pin, and Netmiko refuses a key other than
the pin. It matches the device's name without regard to case, as OpenSSH does. It refuses a pins
file, or its directory, that anyone but you or root can write, as port49 does; port49 also checks
every directory above, which this example does not. It refuses the whole file, naming the line,
if any line is not a plain `name keytype key`: a pattern, a comma list, a hashed name, an `@`
marker, a negation or a port form, since OpenSSH would read those differently from port49.
The example connects on port 22 only: port49 pins a device under its bare address, and Paramiko
looks a key up as `[address]:port` at any other port, so a pin would not be found there.
Public-key authentication and the SSH agent are off, since a refused key counts against the
device's login-attempt limit (policy engine spec §15, L51).

The pin is handed to Netmiko as a 0600 file in a private temporary directory, keyed by the
address Netmiko connects to, and removed once the connection is made or fails. The token is never
printed, including in an error.

Unlike `port49 ssh`, which presents the token once and ends the connection rather than answer a
second prompt, Netmiko's paramiko may present the token a second time: after the device refuses
it by `password`, paramiko can try `keyboard-interactive` with the same token. That is not
measured; a refused token is refused again, one more refused attempt against the device's limits.

Its test runs with neither port49 nor Netmiko installed: `python3 test_port49_netmiko.py`.
