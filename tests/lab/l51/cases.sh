#!/bin/bash
W=$(cat /tmp/l51.workdir); AG=$W/agent.sock
run() { label=$1; user=$2; shift 2; $W/probe4.sh "$label" "$user" -o IdentityFile=none "$@" 2>&1 | sed "s/^debug1: //" ; sleep 6; }
export AGENT=$AG
run C0-agent-default alice12
run C1-pubkeyauth-no alice13 -o PubkeyAuthentication=no
run C2-identityagent-none alice14 -o IdentityAgent=none
run C3-preferred-kbd-pw alice15 -o PreferredAuthentications=keyboard-interactive,password
run Ce-identitiesonly-noI alice16 -o IdentitiesOnly=yes
run Cf-identitiesonly-cert-pubfile alice12 -o IdentitiesOnly=yes -o CertificateFile=$W/kc-cert.pub -i $W/kc.pub
export SSHCONF=$W/conf_g1; run Cg1-host-pubkeyauth-no alice13
export SSHCONF=$W/conf_g2; run Cg2-match-identityagent-none alice14
export SSHCONF=$W/conf_g3; run Cg3-host-preferred alice15
export SSHCONF=$W/conf_h1; run Ch1-snippet-certonly-agent alice16
export SSHCONF=$W/conf_h2; run Ch2-plus-identityfile-pub alice12
export AGENT=; export SSHCONF=$W/conf_h3; run Ch3-cert-and-key-on-disk-no-agent alice13
export SSHCONF=$W/conf_h3b; run Ch3b-cert-and-identityfile-stem-disk-no-agent alice14
export SSHCONF=; run Ch3c-identityfile-stem-only-cert-autopair alice15 -o IdentitiesOnly=yes -i $W/stem/id_l51
export AGENT=$AG; run Ch3d-agent-loaded-explicit-stem-key alice16 -o IdentitiesOnly=yes -i $W/stem/id_l51
