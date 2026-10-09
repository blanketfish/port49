#!/bin/bash
W=$(cat /tmp/l51.workdir); export ADDR=172.100.100.41 L51_NAS=xe1
(sleep 5; for c in 'terminal length 0' 'show login' 'show login failures'; do printf '%s\r' "$c"; sleep 3; done; printf 'exit\r'; sleep 1) | $W/ssh2g.sh 2>&1 | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | tr -d '\r' | sed -n '/show login$/,$p' | grep -E 'Mode|failure count|Watch Window|remaining|Quiet|Information|Username|alice|172' | cut -c1-120
