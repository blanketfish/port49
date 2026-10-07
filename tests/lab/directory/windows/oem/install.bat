@echo off
rem L44 (tests/lab/directory/windows): what the harness needs before it can
rem reach this VM. OpenSSH Server, which Windows Server 2025 installs stopped,
rem started and automatic; the firewall off, because the VM is reached only
rem through the container's ports published on the host's loopback; and
rem Windows Update off, so the build the run measures is the one the pinned
rem ISO installed. The time zone is UTC: QEMU starts the VM's clock at the
rem host's UTC and Windows reads it as local time, so under the image's
rem Pacific zone a kept DC whose container restarted came up 7h out and
rem failed checkSkew (L44 harness review M5). RealTimeIsUniversal instead put
rem a fresh DC 7h behind, as the clock setup wrote held Pacific time (measured
rem 2026-10-07); under UTC local and universal time are the same.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -All -Enabled False; Set-Service sshd -StartupType Automatic; Start-Service sshd; New-Item -Force -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord; Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled; Set-TimeZone -Id 'UTC'"
echo lab: windows ready> C:\OEM\l44-ready.txt
