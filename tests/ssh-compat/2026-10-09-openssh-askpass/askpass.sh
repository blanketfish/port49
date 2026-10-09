#!/bin/sh
# Logs how ssh ran it, then answers with the throwaway password. Never logs the password.
{
  printf 'askpass ran: argv1=[%s] SSH_ASKPASS_PROMPT=[%s] ' "$1" "${SSH_ASKPASS_PROMPT-}"
  if (exec </dev/tty) 2>/dev/null; then echo 'dev_tty=opens'; else echo 'dev_tty=fails'; fi
} >> /tmp/askpass.log
cat /root/pw
