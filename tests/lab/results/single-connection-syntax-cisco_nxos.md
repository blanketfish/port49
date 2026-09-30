# single-connection-syntax — cisco_nxos

- **Date measured:** 2026-09-30
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Capture:** none: the break-glass CLI with port49d stopped, no TACACS+ traffic

## Claim

Where `single-connection` goes on the N9Kv's `tacacs-server host` line relative to `key 0 <key>` (plan 6b Task 19; the line singleConnection types).

## Observation

Each position was typed in configuration mode followed by `?`, then cleared (Ctrl-U) and left without committing. `<key>` stands for the lab key, typed and redacted here.

### `tacacs-server host 172.100.100.1 ?`

Offers `single-connection`: true. The device said:

```
tacacs-server host 172.100.100.1 ?
  <CR>               
  key                TACACS+ shared secret
  port               TACACS+ server port
  single-connection  Use single connection for this Tacacs+ server
  test               Parameters to send test packets
  timeout            TACACS+ server timeout period in seconds

[46D[Jnx1(config)# tacacs-server host 172.100.100.1
```

### `tacacs-server host 172.100.100.1 single-connection ?`

Offers `single-connection`: true. The device said:

```
tacacs-server host 172.100.100.1 single-connection ?
  <CR>   

[64D[Jnx1(config)# tacacs-server host 172.100.100.1 single-connection
```

### `tacacs-server host 172.100.100.1 key 0 <key> ?`

Offers `single-connection`: true. The device said:

```
tacacs-server host 172.100.100.1 key 0 <key> ?
  <CR>               
  port               TACACS+ server port
  single-connection  Use single connection for this Tacacs+ server
  timeout            TACACS+ server timeout period in seconds

[62D[Jnx1(config)# tacacs-server host 172.100.100.1 key 0 <key>
```

### `tacacs-server host 172.100.100.1 key 0 <key> single-connection ?`

Offers `single-connection`: true. The device said:

```
tacacs-server host 172.100.100.1 key 0 <key> single-connection ?
  <CR>   

[80D[Jnx1(config)# tacacs-server host 172.100.100.1 key 0 <key> single-connection
```

