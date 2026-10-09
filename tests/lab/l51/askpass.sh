#!/bin/sh
W=$(cat /tmp/l51.workdir)
echo "$(date +%s) prompt" >> $W/prompts.log
case "$(cat $W/mode)" in
  garbage) printf '%s\n' "l51-not-a-token-0000000000000" ;;
  breakglass) printf '%s\n' "$(cat $W/bgpw)" ;;
  token) jq -r --arg u "$(cat $W/user)" 'select(.nas==$ENV.L51_NAS and .username==$u) | .login' /tmp/port49-lab-tokens.jsonl | head -1 ;;
esac
