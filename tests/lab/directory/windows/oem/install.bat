@echo off
rem L44 (tests/lab/directory/windows): what the harness needs before it can
rem reach this VM. OpenSSH Server, which Windows Server 2025 installs stopped,
rem started and automatic; the firewall off, because the VM is reached only
rem through the container's ports published on the host's loopback; and
rem Windows Update off, so the build the run measures is the one the pinned
rem ISO installed.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -All -Enabled False; Set-Service sshd -StartupType Automatic; Start-Service sshd; New-Item -Force -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord; Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled"
echo lab: windows ready> C:\OEM\l44-ready.txt
