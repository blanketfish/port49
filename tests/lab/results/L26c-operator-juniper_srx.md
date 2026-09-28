# L26c — juniper_srx (operator-reported)

- **Date reported:** 2026-09-25
- **Platform:** SRX-series hardware
- **Image version:** Junos 23.4R2-S8.7
- **Capture:** none. The owner ran these by hand and reported them; no pcap or raw output was
  kept. **This note does not close L26c** (§15 rule 3 needs a capture); it records what the
  hardware showed beside the lab's `L26c-juniper_*.md`.
- **Transport:** SSH, TACACS+ authorization from tac_plus

## Setup

The reply set `local-user-name` to a local template class and sent `user-permissions` and
`deny-commands` as attributes. `show cli authorization` showed the class, the permissions and the
deny list as sent.

## Observation

| # | Reply | Test | Result |
|---|---|---|---|
| 1 | `view view-configuration`, `deny-commands "show configuration security"` | CLI `show configuration`, `show configuration security` | Both run. A deny naming a hierarchy is not enforced (as L26b measured). |
| 2 | `view view-configuration`, a deny naming `show configuration` with a trailing wildcard | CLI `show configuration …` | Runs. |
| 3 | `view view-configuration`, `deny-commands "show configuration"` | CLI `show configuration` | Refused. |
| 4 | same as 3 | `xml-mode netconf`, then `<rpc><get-configuration/></rpc>` | Hello returned; the whole configuration returned, secret values masked. |
| 5 | `view`, `deny-commands "show version"` | CLI `show version` | Refused. |
| 6 | same as 5 | `xml-mode netconf`, then `<rpc><get-software-information/></rpc>` | Refused (permission denied). |
| 7 | `view`, no deny (control for 5 and 6) | the same two | Both run. |
| 8 | denies `(show configuration\|xml-mode)`, `(show configuration\|xml mode netconf)`, `^xml-mode.*`, `.*xml-mode.*`, `xml.*`, `^xml.*$`, `^.*xml.*$` | CLI `xml-mode netconf` | Enters NETCONF in every case. |
| 9 | `deny-commands "^.*$"` | CLI `xml-mode netconf`, and other commands | Refused, as is every other command. |

`xml-mode netconf need-trailer` is not a valid command on this release; plain `xml-mode netconf`
works, and the results do not depend on the argument. No configuration statement was found that
controls `xml-mode`. Where `xml-mode` ran, TACACS+ accounting recorded it as
`cmd=xml-mode netconf <cr>`, and the authorization syslog showed the command as typed, followed
by a UI login event with client mode `netconf`. Rows 1–9 ran with the NETCONF service
(`system services netconf ssh`, on port 830) on. With it deactivated and committed, port 830
stopped listening, and `xml-mode netconf` from an SSH CLI session on port 22 still opened NETCONF, and
`<get-configuration/>` there returned the configuration.
Turning the NETCONF service off does not close `xml-mode`; only turning SSH off would.

## Local class and `junoscript` (reported 2026-09-28)

With the deny set on the local login class instead of sent by TACACS+, the result was the same:
`xml-mode netconf` still opened NETCONF and the configuration could still be read. A
`deny-commands "junoscript"` refused `xml-mode netconf`. The PyEZ list reported the same name
from the allow side (Junos 18.4R3-S2: NETCONF needed `junoscript` allowed, not `xml-mode`), so
Junos appears to authorize `xml-mode` as `junoscript`, which is why no deny naming `xml` matched
(row 8). A `junoscript` deny sent by TACACS+ refused `xml-mode netconf` as the class-level one
did, and in both cases `show version` still ran beside it.

## What it means for port49

- **A wire deny beneath `view-configuration` is not a boundary.** `<get-configuration/>` is
  authorized by the bit, not by `deny-commands` (row 4). This is the case L26c left open ("whether
  an RPC reaches past a deny beneath `view-configuration`"), and it is what option C assumes.
- A deny does bind an operational RPC mapped to its CLI command (rows 5–7), as L26c saw for a
  `<command>` RPC.
- No deny naming `xml-mode` refuses it (row 8); `^.*$` does (row 9, as in the lab). That is why
  the fail-closed and narrow replies send exactly that (`TestTheCatchAllDenyIsExactlyAnchoredDotStar`).
- The management-services allowlist (§8, `devices check-config`) does not close `xml-mode`: it
  runs inside the CLI session, with the NETCONF service off. What keeps port49 safe is option C
  and the `^.*$` catch-all, not the allowlist.
- A `junoscript` deny, sent by TACACS+, closes `xml-mode` without denying everything else. Once
  measured in the lab, port49 could send it and lift option C for grants whose only RPC path is
  `xml-mode` (carried in the roadmap).
- Entering `xml-mode` is visible in accounting, so `port49 devices capabilities` input can show it.
