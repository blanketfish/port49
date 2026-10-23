#!/usr/bin/env bash
# The secret filter every lab log is read through (plan 11b): drops a line naming a password,
# token or secret or holding a JWT, and masks any long run. stdin to stdout; never fails on an
# empty result, so a pipeline under pipefail fails only on the command it filters.
#
# It runs on Linux CI (.github/workflows/lab-free.yml, GNU sed under C.UTF-8) and in vet.sh on
# developer machines, so it is POSIX ERE that BSD sed should accept (not yet run there), and it
# runs under LC_ALL=C so no locale changes what a class matches.
#
# A line holding any byte outside printable ASCII and whitespace is dropped first: NUL, a control
# byte, any byte >= 0x80, valid UTF-8 included. Such a byte splits a run below the mask, as the
# length bytes of a raw TACACS+ body printed with %s would. tr turns NUL into \001 first: a sed
# that ends a string at NUL (busybox's does) would otherwise match only the text before it. It
# turns \v and \f into \001 too, and a CR anywhere but a line's last byte drops the line: as
# whitespace they would split a run as well (TACACS+ length values 11 to 13). Tab and a CRLF
# line's final CR stay. The CR goes in as a literal byte, since POSIX ERE has no \r.
#
# A go test status line that is exactly a name and a duration ("--- FAIL: TestX/token_login
# (1.20s)") is kept, so a red job names its failing test. On it only, each /-separated segment of
# 24 or more characters, or holding eyJ, becomes <LONG>. The bound: a name of short segments prints
# as is, even when / splits a secret into them. The name's class has no + or =, so a line carrying
# base64 is not structural and takes the drop-then-mask the rest do; the duration is go test's own
# %.2f form, at most six digits before the point, so it carries nothing either. Each mask runs as
# two /g passes, not a loop: one pass skips a segment whose leading / its neighbor's match took,
# and the second takes it, so the time stays linear in the line. The % delimiter keeps /
# unescaped: a backslash inside a POSIX bracket is a member, not an escape.
cr=$'\r'
LC_ALL=C tr '\000\013\014' '\001\001\001' | LC_ALL=C sed -E -e "/${cr}./d" -e '
/[^[:print:][:space:]]/d
\%^[[:space:]]*--- (FAIL|PASS|SKIP): [A-Za-z0-9_/.#-]+ \([0-9]{1,6}\.[0-9]{2}s\)$% {
  s%(: |/)[A-Za-z0-9_.#-]{24,}(/| \()%\1<LONG>\2%g
  s%(: |/)[A-Za-z0-9_.#-]{24,}(/| \()%\1<LONG>\2%g
  s%(: |/)[A-Za-z0-9_.#-]*[Ee][Yy][Jj][A-Za-z0-9_.#-]*(/| \()%\1<LONG>\2%g
  s%(: |/)[A-Za-z0-9_.#-]*[Ee][Yy][Jj][A-Za-z0-9_.#-]*(/| \()%\1<LONG>\2%g
  b
}
/[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Ee][Yy][Jj]/d
s%[A-Za-z0-9_+/=.-]{24,}%<LONG>%g
'
