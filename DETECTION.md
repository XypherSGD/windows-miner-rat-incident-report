# How to check whether you have this

Everything here is read only. Nothing in this file changes your system.

**Run PowerShell as Administrator.** This matters more than usual. Several of these checks return empty output when run unelevated, not because the system is clean but because the malware set `HideExclusionsFromLocalAdmins`, and because parts of the registry are simply not readable without elevation. We wasted hours on exactly this mistake. If a check comes back empty, confirm your privilege level before you believe it.

To confirm you are elevated:

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

That must print `True`.

---

## 1. The single most important check

If you only run one thing, run this.

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Recurse -ErrorAction SilentlyContinue |
  ForEach-Object {
    "KEY: $($_.Name)"
    (Get-ItemProperty $_.PSPath).PSObject.Properties |
      Where-Object Name -notlike 'PS*' |
      ForEach-Object { "    $($_.Name) = $($_.Value -join ', ')" }
  }
```

**On a normal home machine this should return nothing, or at most a `UX Configuration` key.**

If you see an `Exclusions` key, a `Policy Manager` key, or values named `HideExclusionsFromLocalAdmins` or `DisableLocalAdminMerge`, something has written Group Policy settings to your Defender configuration.

First confirm you are not actually managed by an employer:

```powershell
dsregcmd /status | Select-String "AzureAdJoined|EnterpriseJoined|DomainJoined"
```

If all three say `NO` and that policy key is populated, it is not legitimate.

---

## 2. LSA authentication packages

```powershell
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages")."Authentication Packages"
```

Expected output on a clean machine:

```
msv1_0
```

You may also legitimately see entries from enterprise single sign on products. What you should not see is a full path to a DLL somewhere in `Program Files` or `ProgramData`. Anything listed here loads into `lsass.exe` as SYSTEM at boot and can observe authentication.

Also check the related keys:

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages","Notification Packages" -ErrorAction SilentlyContinue
```

---

## 3. Known file paths

```powershell
@(
  "C:\ProgramData\Microsoft\Windows\Caches\7527405F",
  "C:\ProgramData\49681505",
  "C:\ProgramData\proxies-peer",
  "C:\ProgramData\HostsServices",
  "C:\Program Files (x86)\Microsoft.VC1438.MFC",
  "$env:LOCALAPPDATA\Microsoft\Windows\Caches\9B361726",
  "$env:LOCALAPPDATA\Microsoft\Windows\8B86CBC",
  "$env:LOCALAPPDATA\proxies-peer",
  "$env:APPDATA\Microsoft\Windows\Caches\7527405F",
  "$env:APPDATA\packetstream",
  "C:\Windows\Temp\HostsServices.exe",
  "C:\Windows\Temp\PacketStreamInstaller-HS.exe"
) | ForEach-Object { "{0,-70} {1}" -f $_, (Test-Path $_) }
```

Folder names will differ on other machines. The hex names (`7527405F`, `9B361726`, `8B86CBC`, `49681505`) are very likely generated per install. Treat the **pattern** as the indicator: short uppercase hex folder names sitting inside real Windows cache directories, containing hidden and system files.

Broader sweep for that pattern:

```powershell
@("C:\ProgramData","C:\ProgramData\Microsoft\Windows\Caches","$env:LOCALAPPDATA\Microsoft\Windows\Caches","$env:APPDATA\Microsoft\Windows\Caches") |
  ForEach-Object {
    Get-ChildItem $_ -Directory -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match '^[0-9A-F]{6,10}$' -or $_.Name -match '^rt-[0-9A-F]+$' } |
      Select-Object FullName, CreationTime
  }
```

---

## 4. All six Run key locations

Most guides check two. Check all six.

```powershell
@(
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
) | ForEach-Object {
  "--- $_"
  Get-ItemProperty $_ -ErrorAction SilentlyContinue |
    Select-Object * -ExcludeProperty PS* | Format-List
}
```

Names seen in this incident: `WinSysCache`, `HostsServices`. Both deliberately boring. Anything invoking `wscript.exe` or `mshta.exe` deserves a hard look regardless of what it is called.

---

## 5. Scheduled tasks, all folders

```powershell
Get-ScheduledTask | ForEach-Object {
  $t = $_
  $t.Actions | ForEach-Object {
    [PSCustomObject]@{
      Task = $t.TaskName; Path = $t.TaskPath
      Execute = $_.Execute; Args = $_.Arguments
    }
  }
} | Where-Object { $_.Execute -notmatch '^%windir%|^C:\\Windows\\System32\\(svchost|rundll32)' } |
  Format-Table -AutoSize | Out-String -Width 300
```

Names seen here: `Windows System Health`, `Windows System Health Check`, `Windows System Health Monitor`, `HostsServices`, `HostsServicesWatchdog`. Note how closely the first three imitate genuine Windows task names.

---

## 6. Services running from unusual locations

```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -and $_.PathName -notmatch '^"?C:\\Windows\\|^"?C:\\Program Files' } |
  Select-Object Name, DisplayName, PathName, State, StartMode | Format-List
```

And specifically for remote access tooling, which is worth checking on any machine:

```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -match 'ScreenConnect|ConnectWise|AnyDesk|TeamViewer|Atera|Splashtop|RustDesk|Supremo|LogMeIn|GoToAssist|VC1438' } |
  Select-Object Name, PathName
```

If you find ScreenConnect and you did not install it, read the arguments. `e=Access` means unattended access with no consent prompt.

---

## 7. Live network connections with owning process

This is the check that found ScreenConnect after we had already declared the machine clean twice. Do not skip it.

```powershell
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemoteAddress -notmatch '^127\.|^::1' } |
  ForEach-Object {
    $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      Remote = "$($_.RemoteAddress):$($_.RemotePort)"
      Process = $p.ProcessName
      Path = $p.Path
    }
  } | Sort-Object Process | Format-Table -AutoSize | Out-String -Width 200
```

Account for every single line. If you cannot name the app responsible for a connection, investigate it.

Specifically for the infrastructure in this incident:

```powershell
Get-NetTCPConnection | Where-Object {
  $_.RemotePort -in 8041,4041,8443 -or
  $_.RemoteAddress -match '198\.23\.185|176\.96\.137|217\.216\.109'
}
```

---

## 8. Trusted root certificate store

```powershell
Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject -eq $_.Issuer } |
  Select-Object Subject, NotAfter, Thumbprint |
  Sort-Object Subject
```

That returns all self signed roots, which on a normal machine is a long list of legitimate CAs. What you are looking for is a company name that has no business being a certificate authority, with a recent issue date. In this case:

```
CN=Dell Technologies, O=Dell Technologies, OU=WU438D, C=US
Thumbprint B60A97B26D731D549B855CE62053D9B33A08AD04
```

Real Dell software is signed by a certificate chaining to a public CA, not by a self signed root called "Dell Technologies" that appeared last Tuesday. Sort by `NotBefore` and look at anything recent.

---

## 9. Firewall rules pointing at odd programs

```powershell
Get-NetFirewallRule -Enabled True | ForEach-Object {
  $af = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
  if ($af.Program -and $af.Program -ne 'Any' -and $af.Program -notmatch '^C:\\Windows|^C:\\Program Files|^%') {
    [PSCustomObject]@{ Name=$_.DisplayName; Dir=$_.Direction; Action=$_.Action; Program=$af.Program }
  }
} | Format-Table -AutoSize | Out-String -Width 200
```

Rules named after the payload (`RuntimeHost`, `SecurityHealthHost`) revealed one payload path we had not otherwise found.

---

## 10. Kernel drivers

The most important negative check. If this comes back empty you are dealing with userland malware, which is removable. If it does not, consider wiping.

```powershell
Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | ForEach-Object {
  $p = $_.PathName -replace '\\\?\?\\',''
  if ($p -and (Test-Path $p)) {
    $s = Get-AuthenticodeSignature $p
    $subj = $s.SignerCertificate.Subject -replace '^CN=([^,]+).*','$1'
    if ($s.Status -ne 'Valid' -or $subj -notmatch 'Microsoft') {
      [PSCustomObject]@{ Name=$_.Name; Status=$s.Status; Signer=$subj }
    }
  }
} | Format-Table -AutoSize
```

---

## 11. Among Us specifically

```powershell
$au = "C:\Program Files (x86)\Steam\steamapps\common\Among Us"
@("$au\BepInEx","$au\winhttp.dll","$au\doorstop_config.ini","$au\.doorstop_version") |
  ForEach-Object { "{0,-70} {1}" -f $_, (Test-Path $_) }
Get-ChildItem "$au\BepInEx\plugins" -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime
```

Note that BepInEx presence alone is not proof of malware. It is a legitimate modding framework and plenty of harmless mods use it. The question is what is in `plugins`.

Check where any mod zip in your Downloads came from:

```powershell
Get-ChildItem "$env:USERPROFILE\Downloads" -Filter *.zip | ForEach-Object {
  $z = Get-Content "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
  if ($z) { $_.Name; $z | Where-Object { $_ -match 'ReferrerUrl|HostUrl' }; "" }
}
```

---

## 12. Verify Defender is actually allowed to scan

Even after cleanup, confirm the exclusion list is sane.

```powershell
(Get-MpPreference).ExclusionPath
(Get-MpPreference).ExclusionProcess
Get-MpComputerStatus | Select-Object IsTamperProtected, RealTimeProtectionEnabled, AntivirusEnabled
```

A clean Windows 11 install has an empty exclusion list. Developer tooling legitimately adds `.NET Framework` and Temp paths, so those are not automatically suspicious, but anything pointing into `ProgramData`, `AppData`, or naming a miner binary is.

`IsTamperProtected` should be `True`. If the Windows Security UI says Tamper Protection is "managed by your administrator" and you have no administrator, go back to check 1.

**Do not trust a clean scan result until this check passes.** A scan only covers what it is permitted to cover, and in this incident the Defender Offline scan returned clean while sitting directly on top of the infection.
