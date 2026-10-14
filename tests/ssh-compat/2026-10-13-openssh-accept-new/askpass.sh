#!/bin/sh
# Plan 9d, cells g1c: logs who ran it (its parent's pid and command line) and
# the prompt it was given, one tab-separated line to $ASKLOG, and fails. It never
# has, and never logs, a password.
printf '%s\t%s\t%s\n' "$PPID" "$(tr '\0' ' ' < "/proc/$PPID/cmdline")" "$(printf '%s' "$1" | tr '\n' ' ')" >> "$ASKLOG"
exit 1
