# L44: stop the DC's KDC for OR-1's cell, with a one-shot SYSTEM task that
# starts it again restart_after seconds later (an SSH logon to a DC fails
# while its KDC is down, so the start cannot come over SSH); or, once SSH
# answers again, report the KDC and the task and remove the task.
param([string]$name, [string]$state, [int]$restart_after)
$ErrorActionPreference = 'Stop'
if ($name -ne 'Kdc') { throw "not a service this lab stops: $name" }
$task = 'port49-l44-kdc-start'
if ($state -eq 'stop') {
  if ($restart_after -lt 30) { throw "restart_after too short: $restart_after" }
  New-Item -ItemType Directory -Force C:\l44 | Out-Null
  Set-Content C:\l44\kdc-start.ps1 -Encoding ascii -Value @'
for ($i = 0; $i -lt 24; $i++) {
  try { Start-Service Kdc -ErrorAction Stop } catch {}
  if ((Get-Service Kdc).Status -eq 'Running') { exit 0 }
  Start-Sleep 5
}
exit 1
'@
  $at = (Get-Date).AddSeconds($restart_after)
  $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\l44\kdc-start.ps1'
  $p = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $s = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
  Register-ScheduledTask -TaskName $task -Action $a -Trigger (New-ScheduledTaskTrigger -Once -At $at) -Principal $p -Settings $s -Force | Out-Null
  Stop-Service Kdc -Force
  $deadline = (Get-Date).AddMinutes(2)
  while ((Get-Service Kdc).Status -ne 'Stopped') { if ((Get-Date) -gt $deadline) { throw 'Kdc did not stop' }; Start-Sleep 1 }
  @{ name = 'Kdc'; status = "$((Get-Service Kdc).Status)"; stopped_at = [DateTime]::UtcNow.ToString('o'); start_at = $at.ToUniversalTime().ToString('o') }
} elseif ($state -eq 'check') {
  $i = Get-ScheduledTaskInfo -TaskName $task -ErrorAction SilentlyContinue
  $r = @{ name = 'Kdc'; status = "$((Get-Service Kdc).Status)"; now = [DateTime]::UtcNow.ToString('o')
          task_ran = $(if ($i) { $i.LastRunTime.ToUniversalTime().ToString('o') } else { '' }); task_result = "$($i.LastTaskResult)" }
  Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
  Remove-Item C:\l44\kdc-start.ps1 -ErrorAction SilentlyContinue
  $r.task_left = [bool](Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)
  $r
} else { throw "not a state: $state" }
