#!/usr/bin/env bash
# The secret filter every lab log is read through (plan 11b): drops a line naming a password,
# token or secret or holding a JWT, and masks any long run. stdin to stdout; never fails on an
# empty result, so a pipeline under pipefail fails only on the command it filters.
#
# A go test status line that is exactly a name and a duration ("--- FAIL: TestX/token_login
# (1.20s)") is kept, so a red job names its failing test. On it only, each /-separated segment of
# 24 or more characters, or holding eyJ, becomes <LONG>. The name's class has no + or =, so a
# line carrying base64 is not structural and takes the drop-then-mask the rest do. The % delimiter
# keeps / unescaped: a backslash inside a POSIX bracket is a member, not an escape.
sed -E '
\%^[[:space:]]*--- (FAIL|PASS|SKIP): [A-Za-z0-9_/.#-]+ \([0-9.]+s\)$% {
  :long
  s%(: |/)[A-Za-z0-9_.#-]{24,}(/| \()%\1<LONG>\2%
  t long
  :jwt
  s%(: |/)[A-Za-z0-9_.#-]*[Ee][Yy][Jj][A-Za-z0-9_.#-]*(/| \()%\1<LONG>\2%
  t jwt
  b
}
/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Ee][Yy][Jj]/d
s%[A-Za-z0-9_+/=.-]{24,}%<LONG>%g
'
