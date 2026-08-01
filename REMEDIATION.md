# Cleanup, in the order that actually works

Order matters here. I did this out of order several times and each time the machine repaired itself on the next reboot. The sequence below is the one that finally held.

Everything needs an **elevated** PowerShell.

> A note before you start. If the machine holds anything genuinely valuable, or if you found an entry in the LSA `Authentication Packages` key, the correct answer is to back up your files and reinstall Windows. Cleaning worked for me and I have documented why I was comfortable with that (no kernel drivers, every persistence mechanism accounted for), but a wipe is the only way to be certain. Do not let a writeup that says "I cleaned it" talk you out of the safer option.

---

## Step 0. Disconnect from the internet

If you found a live remote access session, pull the network first. Wi-Fi off or cable out. Everything below works offline.

You lose the ability to look things up while you work, so read through the whole document before you disconnect.

---

## Step 1. Kill the Group Policy tampering FIRST

This is step one for a reason. While `DisableLocalAdminMerge` is set, every exclusion change you make is silently reverted, and while the malicious exclusions stand, every scan you run is blind. Nothing else you do is reliable until this is gone.

```powershell
$base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

# Dump it first so you have a record of what was set
Get-ChildItem $base -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
  "KEY: $($_.Name)"
  (Get-ItemProperty $_.PSPath).PSObject.Properties |
    Where-Object Name -notlike 'PS*' |
    ForEach-Object { "    $($_.Name) = $($_.Value -join ', ')" }
}

# Then remove
Remove-Item "$base\Exclusions"     -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$base\Policy Manager" -Recurse -Force -ErrorAction SilentlyContinue

gpupdate /force /target:computer
Restart-Service WinDefend -Force
Start-Sleep 5

# Verify
(Get-MpPreference).ExclusionPath
(Get-MpPreference).ExclusionProcess
```

The exclusion list should now be empty or contain only benign developer paths. If entries you did not add are still there, the policy key is still populated somewhere. Do not proceed until this is clean.

Only delete `Exclusions` and `Policy Manager`. Leave `UX Configuration` alone, it is harmless. Windows may recreate an empty `Policy Manager` container afterwards, which is normal as long as it has no values in it.

If you prefer regedit: navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`, right click `Exclusions`, delete, same for `Policy Manager`, then reboot.

---

## Step 2. Remove persistence before touching files

Kill the triggers first so nothing relaunches while you are deleting.

```powershell
# Run keys, all six locations
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WinSysCache" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "HostsServices" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "WinSysCache" -Force -ErrorAction SilentlyContinue

# Scheduled tasks
"Windows System Health","Windows System Health Check","Windows System Health Monitor","HostsServices","HostsServicesWatchdog" |
  ForEach-Object { Unregister-ScheduledTask -TaskName $_ -Confirm:$false -ErrorAction SilentlyContinue }

# Startup shortcuts (hidden, so -Force is required to even see them)
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\RuntimeHost.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\PacketStream.lnk" -Force -ErrorAction SilentlyContinue
```

Re-run the check from [DETECTION.md](DETECTION.md) section 4 afterwards and confirm all six Run locations are clean. The `WOW6432Node` one restored everything for me once because I had not checked it.

---

## Step 3. The LSA authentication package

Do this before trying to delete the DLL. The file cannot be removed while LSA has it loaded, and no amount of `takeown`, `icacls` or `rmdir` will change that. I tried all of them.

```powershell
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$current = (Get-ItemProperty $lsaPath -Name "Authentication Packages")."Authentication Packages"
$current   # look at this before changing it

$clean = $current | Where-Object { $_ -notmatch 'ScreenConnect|VC1438' }
$clean     # this MUST still contain msv1_0

Set-ItemProperty -Path $lsaPath -Name "Authentication Packages" -Value $clean -Type MultiString
(Get-ItemProperty $lsaPath -Name "Authentication Packages")."Authentication Packages"
```

**Check the value before and after.** If you remove `msv1_0` by accident you will have a bad time at the next login. The result should be `msv1_0` and nothing else.

Then reboot. LSA only reads that list at boot, so the DLL stays loaded until you do.

After the reboot the file deletes normally.

---

## Step 4. Stop services and processes, then delete files

```powershell
# ScreenConnect service, found by path rather than name since the name varies
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'ScreenConnect|VC1438' } | ForEach-Object {
  Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
  sc.exe delete $_.Name
}

Get-Process | Where-Object {
  $_.Path -match 'ScreenConnect|VC1438|RuntimeHost|SecurityHealthHost|packetstream|psclient|pslauncher|HostsServices|lolMiner|SRBMiner'
} | Stop-Process -Force -ErrorAction SilentlyContinue

Start-Sleep 2

@(
  "C:\ProgramData\Microsoft\Windows\Caches\7527405F",
  "C:\ProgramData\49681505",
  "C:\ProgramData\proxies-peer",
  "C:\ProgramData\HostsServices",
  "C:\Program Files (x86)\Microsoft.VC1438.MFC",
  "$env:LOCALAPPDATA\Microsoft\Windows\Caches\9B361726",
  "$env:LOCALAPPDATA\Microsoft\Windows\Caches\rt-8B86CBC",
  "$env:LOCALAPPDATA\Microsoft\Windows\8B86CBC",
  "$env:LOCALAPPDATA\proxies-peer",
  "$env:APPDATA\Microsoft\Windows\Caches\7527405F",
  "$env:APPDATA\packetstream"
) | ForEach-Object { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue }

Remove-Item "C:\Windows\Temp\HostsServices.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\Temp\PacketStreamInstaller-HS.exe" -Force -ErrorAction SilentlyContinue
```

If something refuses to delete and nothing appears to be holding it, schedule it for removal at next boot:

```powershell
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class W { [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
  public static extern bool MoveFileEx(string a, string b, int f); }
'@
[W]::MoveFileEx("C:\path\to\stubborn.file", $null, 0x4)
```

---

## Step 5. Remove the forged certificate

Easy to overlook and it outlives everything else. While it is installed, any future payload signed with the matching key passes as trusted.

```powershell
$thumb = "B60A97B26D731D549B855CE62053D9B33A08AD04"   # yours may differ, find it via DETECTION.md section 8
Get-ChildItem Cert:\LocalMachine -Recurse |
  Where-Object { $_.Thumbprint -eq $thumb } |
  ForEach-Object { Remove-Item $_.PSPath -Force }

# verify
Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object { $_.Thumbprint -eq $thumb }
```

---

## Step 6. Firewall rules

```powershell
"RuntimeHost","SecurityHealthHost" | ForEach-Object {
  Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-NetFirewallRule -Name $_.Name }
}
```

While you are here, clear out rules for any app you have since uninstalled.

---

## Step 7. The delivery vehicle

For Among Us specifically:

```powershell
$au = "C:\Program Files (x86)\Steam\steamapps\common\Among Us"
Remove-Item "$au\BepInEx" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$au\winhttp.dll" -Force -ErrorAction SilentlyContinue
Remove-Item "$au\doorstop_config.ini" -Force -ErrorAction SilentlyContinue
Remove-Item "$au\.doorstop_version" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Downloads\HyperMenu-Install.zip" -Force -ErrorAction SilentlyContinue
```

Then uninstall the game in Steam and reinstall it. A full uninstall is better than "Verify integrity of game files" because it removes the folder outright rather than patching over what is there.

Delete the installer from Downloads so you cannot reinstall it by accident at 3am.

---

## Step 8. Turn Tamper Protection back on

Windows Security, Virus and threat protection, Manage settings, Tamper Protection, on.

If it still says "managed by your administrator", the policy key from step 1 is still there.

```powershell
Get-MpComputerStatus | Select-Object IsTamperProtected, RealTimeProtectionEnabled, AntivirusEnabled
```

Worth understanding: once Tamper Protection is on, `Remove-MpPreference` is blocked by design, so exclusions have to be managed through the UI. That is correct behaviour and it is the mechanism that would have prevented the original tampering had it been enabled.

---

## Step 9. Reboot, then verify

```powershell
# Nothing came back
@("C:\ProgramData\Microsoft\Windows\Caches\7527405F","C:\ProgramData\proxies-peer",
  "C:\ProgramData\HostsServices","C:\Program Files (x86)\Microsoft.VC1438.MFC",
  "$env:APPDATA\packetstream") | ForEach-Object { "{0,-60} {1}" -f $_, (Test-Path $_) }

# LSA clean
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages")."Authentication Packages"

# Policy hive clean
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName

# Exclusions clean
(Get-MpPreference).ExclusionPath
(Get-MpPreference).ExclusionProcess

# No connections to the old infrastructure
Get-NetTCPConnection | Where-Object { $_.RemotePort -in 8041,4041,8443 }
```

Reboot at least once and re-run all of it. Several components in this incident only reappeared after a restart, which is the whole point of persistence. A check that passes before a reboot proves very little.

---

## Step 10. Now, finally, scan

Update signatures first, since the machine may have been blocked from updating:

```powershell
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate
```

Then run **Microsoft Defender Offline scan** (Windows Security, Virus and threat protection, Scan options). It reboots and scans before Windows loads, so nothing can hide from it or lock files against it.

This is the first scan whose result means anything, because it is the first one running without the attacker's exclusion list in place. Every scan before step 1 was skipping the infected folders.

---

## Step 11. Assume your credentials are gone

If you found the LSA package, this is not optional and it is more urgent than anything above.

From a **different device**, ideally a phone on mobile data rather than the same network:

1. Email first. It is the password reset path for everything else.
2. Banking and anything with card details saved.
3. Everything else: Steam, Discord, GitHub, game accounts, social.
4. Turn on two factor authentication wherever it is offered.
5. If you had card numbers saved in a browser on that machine, call your bank.

Change them from the clean device, not from the machine you just cleaned.

---

## Step 12. Fix the actual root cause

Everything above is treating symptoms. The cause was installing a game cheat from a random GitHub repository.

Game cheats, mod menus, cracked software and key generators are the single most reliable malware delivery channel aimed at people who are otherwise reasonably careful. They work because you expect them to be unsigned, you expect antivirus to complain, and you are already primed to click through the warning and add an exclusion. The social engineering is done before you download the file.

If you want game mods, take them from the established community registries for that game where uploads are visible and moderated, not from a repo you found in a Discord link.
