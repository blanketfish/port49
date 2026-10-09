#!/bin/sh
# Container setup: sshd plus a throwaway user whose throwaway password lives only in /root/pw.
set -e
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq openssh-server openssh-client expect procps >/dev/null 2>&1
  mkdir -p /run/sshd
else
  dnf install -y -q openssh-server openssh-clients expect util-linux procps-ng passwd >/dev/null 2>&1
fi
rm -f /run/nologin /var/run/nologin
ssh-keygen -A >/dev/null
useradd -m -s /bin/bash tuser
umask 077
head -c 18 /dev/urandom | base64 | tr -d '\n' > /root/pw
printf 'tuser:%s\n' "$(cat /root/pw)" | chpasswd
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
/usr/sbin/sshd
install -m 0755 /work/askpass.sh /usr/local/bin/askpass
echo "client: $(ssh -V 2>&1)"
echo "setsid: $(setsid --version 2>&1)"
echo "expect: $(expect -v 2>&1)"
mkdir -p /root/.ssh /home/tuser/.ssh
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/ctl
cp /root/.ssh/ctl.pub /home/tuser/.ssh/authorized_keys
chown -R tuser /home/tuser/.ssh; chmod 700 /home/tuser/.ssh
