# L88: the reference AAA configuration on Catalyst 8000V 17.18.02

Platform: cisco_iosxe. Image: Catalyst 8000V 17.18.02. Transport: tls. Measured 2026-11-04 by TestL88.

- cells run over RFC 9887: a, b, d, e, f. c, g, i: not transport-dependent, measured on the plain pass (L88-cisco_iosxe-iosxe1718.md)
- port49d's server certificate carries both server addresses (172.100.100.1, 172.100.100.2) as IP names, because cell f has the device dial the second one; with the first alone, a device that checks the dialled address would refuse the second server for the certificate, not for failover
- RFC 9887 enrolment by L73's machinery (its own PKI; the device's key and certificate id `l73-dev`, the root trusted as `port49-root`); port49d's tls_listener on 172.100.100.1:300. The reference TLS file was then applied over it unchanged.
- the reference loaded: `deploy/device-aaa/cisco_iosxe` (tls), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

Capture: `tests/lab/evidence/L88-f-tls-iosxe1718-cisco_iosxe.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 5.563s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +6s |
| b | PASS | break-glass login with port49d stopped: ok true in 20ms (no error) |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 770ms, `show version` output "'Cisco IOS XE Software, Version 17.18.02'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 2 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 2; port49 authorized one command and denied the other; command output: [0] Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.18.2, RELEASE SOFTWARE (fc3) Technical Support: http://www.cisco.c... [1]   |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 790ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 1s; first command output:  |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=tty434
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=tty434
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=tty435
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=tty435
  event=account verdict= reason= flags=start user=alice01 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=tty435
  event=account verdict= reason= flags=stop user=alice01 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=tty435
  event=account verdict= reason= flags=stop user=alice01 port=tty435
  event=authorize_command verdict=deny reason=no_permit_dominates_deny flags= user=alice01 port=tty435
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=tty434
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=tty434
  event=account verdict= reason= flags=start user=alice02 port=tty434
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=tty434
  event=account verdict= reason= flags=stop user=alice02 port=tty434
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=tty434
  event=account verdict= reason= flags=stop user=alice02 port=tty434
the wire during the login (headers only):
3 connections from the device in the window: 3 with a SYN, 3 answered SYN-ACK, 1 with an RST
+0s 172.100.100.1 sport 33682: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 34752: SYN true SYN-ACK true; device packets 36, server packets 24; FIN dev false srv false; RST dev false srv false
+400ms 172.100.100.2 sport 34768: SYN true SYN-ACK true; device packets 22, server packets 14; FIN dev false srv false; RST dev false srv false

`terminal length 0` after f:
terminal length 0
xe1#
`show tacacs` after f:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 300
              Socket opens:          1
             Socket closes:          0
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:          0
        Total Packets Sent:          0
        Total Packets Recv:          0
          Expected Replies:          0
             Server Status: Dead
Continous Authc fail count:          0
Continous Authz fail count:          3
TACACS+ Secure Server Statistics:
     Packet count since last idletimeout: 26
                    Send handshake count: 5
                       Handshake Success: 5
               Total Packets Transmitted: 26
                  Total Packets Received: 0
                 Total Connection Resets: 84
    Connection Reset due to idle timeout: 0
     Connection Reset due to No Response: 79
Connection Reset due to Malformed packet: 5
                Connection Reset by Peer: 5
    Connection Reset due to other Errors: 0
Test Packet Count since watchdog timeout: 0
Test Packet Count since connection reset: 0


Tacacs+ Server -  public  :
               Server name: port49-2
            Server address: 172.100.100.2
               Server port: 300
              Socket opens:          1
             Socket closes:          0
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:          0
        Total Packets Sent:          0
        Total Packets Recv:          0
          Expected Replies:          0
             Server Status: Dead
Continous Authc fail count:          0
Continous Authz fail count:          3
TACACS+ Secure Server Statistics:
     Packet count since last idletimeout: 9
                    Send handshake count: 2
                       Handshake Success: 2
               Total Packets Transmitted: 9
                  Total Packets Received: 0
                 Total Connection Resets: 78
    Connection Reset due to idle timeout: 0
     Connection Reset due to No Response: 76
Connection Reset due to Malformed packet: 2
                Connection Reset by Peer: 2
    Connection Reset due to other Errors: 0
Test Packet Count since watchdog timeout: 0
Test Packet Count since connection reset: 0

xe1#
`show tcp brief` after f:
show tcp brief
TCB       Local Address               Foreign Address             (state)
7E84675CCE80  10.0.0.15.27990            172.100.100.2.300           CLOSING
7E846E7BBCA0  10.0.0.15.22               172.100.100.1.56732         ESTAB
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS` after f:
show processes | include TACACS
 732 Mwe 605E305750A5             2        145      13  22208/24000  0 TACACS+         
xe1#

```
