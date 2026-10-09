#!/bin/bash
W=$(cat /tmp/l51.workdir); export ADDR=172.100.100.41 L51_NAS=xe1 REMOTE_CMD='show privilege' AGENT=
for i in 1 2 3 4 5 6 7 8; do $W/tok.sh Seq$i alice14 -o PubkeyAuthentication=no | cut -c1-140; sleep 12; done
