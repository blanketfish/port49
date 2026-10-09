#!/bin/sh
# Test 3: the prompts the askpass is given, with HostKeyAlias=dev1, for each method the device may
# take. Run after setup.sh. ssh runs setsid with DISPLAY set, so it asks the askpass.
A=/usr/local/bin/askpass
go() {
  : > /tmp/askpass.log
  DISPLAY=:0 SSH_ASKPASS=$A setsid -w ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o HostKeyAlias=dev1 -o PubkeyAuthentication=no \
    -o PreferredAuthentications=keyboard-interactive,password -o NumberOfPasswordPrompts=1 \
    tuser@127.0.0.1 true </dev/null
  echo "  ssh exit $?"
  sed 's/^/  /' /tmp/askpass.log
}
echo "T3 password (server offers password only):"
go
echo "T3 keyboard-interactive (server offers keyboard-interactive only, through PAM):"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/; s/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/; s/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
grep -q '^ChallengeResponseAuthentication yes' /etc/ssh/sshd_config || echo 'ChallengeResponseAuthentication yes' >> /etc/ssh/sshd_config
pkill -x sshd; sleep 1; /usr/sbin/sshd
go

# Test 5: SIGWINCH forwarding. With ssh in its own session, the parent forwards SIGWINCH.
echo "T5 forwarding SIGWINCH to the setsid'd ssh (password auth again):"
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
pkill -x sshd; sleep 1; /usr/sbin/sshd
expect -f /work/t5.exp
