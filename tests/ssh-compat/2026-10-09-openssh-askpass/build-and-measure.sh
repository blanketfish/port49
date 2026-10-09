#!/bin/sh
# Builds an upstream OpenSSH client from source inside an ubuntu:20.04 container, then runs test 1
# (force) and test 3 (the prompts) with it against the container's own sshd. $1 is the version,
# for example 8.4p1 or 8.5p1; the tarball, from
# https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/, is in /work.
set -e
v=$1
sh /work/setup.sh | head -1
apt-get install -y -qq build-essential zlib1g-dev libssl-dev >/dev/null 2>&1
cd /tmp && tar xzf /work/openssh-$v.tar.gz && cd openssh-$v
./configure -q >/dev/null 2>&1 && make -s -j8 ssh >/dev/null 2>&1
mkdir -p /opt/b && cp ssh /opt/b/ssh
export PATH=/opt/b:$PATH
echo "built: $(ssh -V 2>&1)"
: > /tmp/askpass.log
expect -f /work/t1.exp force,no-DISPLAY SSH_ASKPASS=/usr/local/bin/askpass SSH_ASKPASS_REQUIRE=force
sed 's/^/  /' /tmp/askpass.log
sh /work/t3.sh 2>&1 | sed -n 1,7p
