#!/usr/bin/env bash
# The secret filter every lab log is read through (plan 11b): drops a line naming a password,
# token or secret or holding a JWT, and masks any long run. stdin to stdout; never fails on an
# empty result, so a pipeline under pipefail fails only on the command it filters.
grep -v -i 'password\|token\|secret\|eyJ' | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g' || true
