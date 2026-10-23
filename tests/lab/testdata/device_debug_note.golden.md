What cisco_iosxe's own TACACS+ debug says about the TLS cells of a qualification run on Test Router 1.2.3: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

Platform cisco_iosxe, image Test Router 1.2.3. Debug on: `terminal length 0`, `terminal width 511`, `clear logging`, `<enter>`, `debug tacacs`, `debug aaa authentication`, `debug aaa authorization`, `debug aaa accounting` (read with `show logging`; off with `undebug all`).

### What the filter kept

- `tls_token_login`: the device returned 700 log lines and the filter kept 7 (3 connection open/close, 3 request, 1 other); the capture holds 2 TLS connection(s).
  Lines dropped by rule: facility=0 payload=0 hex_view=0 hex_message=0 evidence_marker=0 stripped_secret_hex=0.
  - debug connections opened=2 closed=1 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=09:48:29.345 closed=09:48:30.001 reason="" authen=1 author=0 acct=1.
  - debug connection 2: opened=09:48:30.100 closed=open reason="" authen=0 author=1 acct=0.
  - capture: `conn port=57518 syn=09:48:29.345 hold=0.03s end=server-fin`
  - capture: `conn port=57532 syn=09:48:30.090 hold=open end=open`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.
- `tls_unknown_ca`: the device returned 400 log lines and the filter kept 2 (1 connection open/close, 0 request, 1 other); the capture holds 1 TLS connection(s).
  Lines dropped by rule: facility=0 payload=0 hex_view=0 hex_message=0 evidence_marker=0 stripped_secret_hex=0.
  - debug connections opened=0 closed=1 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=before closed=09:49:01.050 reason="" authen=0 author=0 acct=0.
  - capture: `conn port=57600 syn=09:49:00.990 hold=0.08s end=server-rst`

### Open questions

- **Which debug line marks a connection open?** `tls_token_login`: `*Oct 23 09:48:29.345: TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (fd 7)` (2 in the cell).
- **tls_token_login: why does the device open a second connection?** The debug shows the second open at `*Oct 23 09:48:30.100: TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (fd 8)`, after `*Oct 23 09:48:30.001: TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)`. That is the line that comes before it, not a stated cause.
- **How does a connection end?** `tls_unknown_ca`: close `*Oct 23 09:49:01.050: TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)`; `tls_token_login`: close `*Oct 23 09:48:30.001: TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)`.
- **Do requests ride one connection together (pipelining)?** 1 of 2 debug connection(s) carried more than one request (3 request line(s)); first request line `*Oct 23 09:48:29.345: TPLUS: processing authentication login request id 1`.

### Shapes of the lines the filter dropped

Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.

`tls_token_login`: 2 shape(s)

- `show logging => _ tplus _ cmd _ debug tacacs _`
- `show logging => _ tac _ handle tacacs _ secure message _`

`tls_unknown_ca`: 1 shape(s)

- `show logging => _ author _ cmd _`
