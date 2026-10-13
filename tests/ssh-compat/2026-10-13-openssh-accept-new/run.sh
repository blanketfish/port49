#!/bin/sh
# Plan 9d, gate G1 and the ssh -G forms, inside one container. $1 is
# "distro" (the image's own OpenSSH client) or an upstream version to build
# (8.5p1), whose tarball's SHA-256 is pinned below. Nothing of plan 9a's
# harness is used.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq openssh-server openssh-client curl ca-certificates >/dev/null 2>&1
if [ "$1" != distro ]; then
  v=$1
  case $v in
    # Written when the tarball was first fetched, after `gpg --verify` of its
    # .asc against the OpenSSH release key; the note records it.
    8.5p1) sum=f52f3f41d429aa9918e38cf200af225ccdd8e66f052da572870c89737646ec25 ;;
    *) echo "run.sh: no pinned checksum for $v" >&2; exit 1 ;;
  esac
  apt-get install -y -qq build-essential zlib1g-dev libssl-dev >/dev/null 2>&1
  cd /tmp
  curl -fsSLO "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$v.tar.gz"
  echo "$sum  openssh-$v.tar.gz" | sha256sum -c -
  tar xzf "openssh-$v.tar.gz" && cd "openssh-$v"
  ./configure -q >/dev/null 2>&1 && make -s -j8 ssh >/dev/null 2>&1
  mkdir -p /opt/b && cp ssh /opt/b/ssh
  export PATH=/opt/b:$PATH
fi
echo "client: $(ssh -V 2>&1)"
mkdir -p /run/sshd && ssh-keygen -A >/dev/null
useradd -m -s /bin/sh tuser
# The jump hop of cell g1c: it asks for a password, which its askpass never has.
useradd -m -s /bin/sh jumpuser && echo jumpuser:x | chpasswd
mkdir -p /root/.ssh /home/tuser/.ssh
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/ctl
cp /root/.ssh/ctl.pub /home/tuser/.ssh/authorized_keys
chown -R tuser /home/tuser/.ssh && chmod 700 /home/tuser/.ssh
/usr/sbin/sshd
# UsePAM yes: this -f config replaces the distro's, and without PAM sshd refuses
# tuser, whose account is locked, so g1-control could never exit 0.
# In serve mode the host's client reaches it through docker's published port,
# which a 127.0.0.1 listener inside the container never sees.
la=127.0.0.1; [ "$2" = serve ] && la=0.0.0.0
printf 'Port 2222\nListenAddress %s\nHostKey /etc/ssh/ssh_host_ed25519_key\nPasswordAuthentication no\nUsePAM yes\n' "$la" \
  > /etc/ssh/sshd_g1
/usr/sbin/sshd -f /etc/ssh/sshd_g1
# The impostor's positive control: port 2222 offers Ed25519 and nothing else.
ssh-keyscan -p 2222 127.0.0.1 2>/dev/null | awk '{print $2}' | sort -u > /tmp/g1types
[ "$(cat /tmp/g1types)" = ssh-ed25519 ] || { echo "INVALID: port 2222 offers $(cat /tmp/g1types)"; exit 1; }
[ "$2" = serve ] && exec sleep infinity
sh /work/keys.sh
