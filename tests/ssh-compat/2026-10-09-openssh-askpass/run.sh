#!/bin/sh
# Runs inside each container.
sh /work/setup.sh || exit 1
: > /tmp/askpass.log
A=/usr/local/bin/askpass
expect -f /work/t1.exp "no-require+DISPLAY" "SSH_ASKPASS=$A" "DISPLAY=:0"
expect -f /work/t1.exp "force,no-DISPLAY" "SSH_ASKPASS=$A" "SSH_ASKPASS_REQUIRE=force"
expect -f /work/t1.exp "force+DISPLAY" "SSH_ASKPASS=$A" "SSH_ASKPASS_REQUIRE=force" "DISPLAY=:0"
echo "askpass log after test 1:"; sed 's/^/  /' /tmp/askpass.log; : > /tmp/askpass.log

echo "T2a no pty at all, setsid, DISPLAY set, stdin piped:"
printf 'line-one\nline-two\n' | DISPLAY=:0 SSH_ASKPASS=$A setsid -w ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no \
  -o PreferredAuthentications=keyboard-interactive,password tuser@127.0.0.1 'cat; exit 3'
echo "  ssh exit $?"
echo "T2a' same without DISPLAY:"
printf 'x\n' | SSH_ASKPASS=$A setsid -w ssh -o StrictHostKeyChecking=no -o BatchMode=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
  -o PreferredAuthentications=keyboard-interactive,password tuser@127.0.0.1 'cat' 2>&1 | sed 's/^/  /'
echo "askpass log after T2a:"; sed 's/^/  /' /tmp/askpass.log; : > /tmp/askpass.log

expect -f /work/t2.exp control
echo "askpass log after T2 control:"; sed 's/^/  /' /tmp/askpass.log; : > /tmp/askpass.log
expect -f /work/t2.exp setsid
echo "askpass log after T2 setsid:"; sed 's/^/  /' /tmp/askpass.log
