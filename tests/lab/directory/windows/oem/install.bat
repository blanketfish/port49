@echo off
rem L44 (tests/lab/directory/windows): what the harness needs before it can
rem reach this VM. OpenSSH Server, which Windows Server 2025 installs stopped,
rem started and automatic; the firewall off, because the VM is reached only
rem through the container's ports published on the host's loopback; and
rem Windows Update off, so the build the run measures is the one the pinned
rem ISO installed. RealTimeIsUniversal: the VM's clock is UTC, which Windows
rem otherwise reads as local time, so a kept DC whose container restarts came
rem up hours out and failed checkSkew (L44 harness review M5).
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -All -Enabled False; Set-Service sshd -StartupType Automatic; Start-Service sshd; New-Item -Force -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord; Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -Name RealTimeIsUniversal -Value 1 -Type DWord"
echo lab: windows ready> C:\OEM\l44-ready.txt
