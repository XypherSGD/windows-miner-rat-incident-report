# The attacker's setup script, recovered in full

This is the single most useful artifact from the whole incident, and I nearly missed it. It is the environment hardening script the attacker ran as SYSTEM before deploying any payload. I recovered it from the PowerShell operational event log two days after the fact.

## How it survived

The script's own section 3 turns off PowerShell script block logging:

```powershell
# === 3. Script Block Logging Disable ===
$slPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if(!(Test-Path $slPath)){New-Item -Path $slPath -Force|Out-Null}
Set-ItemProperty -Path $slPath -Name EnableScriptBlockLogging -Value 0 -Force
```

But PowerShell logs a script block when it **compiles** it, which happens before any line of it executes. So the script was written to the event log in full, in the same instant it was switching logging off. It disabled logging for everything that came after, and left a complete copy of itself behind.

That is why I have the next 180 lines and why there is almost nothing in the logs after 14:31 on July 31st.

## Recovering it yourself

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = (Get-Date "2026-07-31 00:00")
    EndTime   = (Get-Date "2026-08-01 00:00")
} | Where-Object { $_.UserId -eq 'S-1-5-18' } | Sort-Object TimeCreated |
  ForEach-Object { $_.Message -replace '(?s)^Creating Scriptblock text \(\d+ of \d+\):\s*','' }
```

`S-1-5-18` is `NT AUTHORITY\SYSTEM`. Filtering on it separates attacker activity from your own PowerShell use very effectively. On my machine that day there were 190 script block events, 153 from my user account (my own tooling, plus stock Windows scripts) and 37 from SYSTEM. All 35 of the interesting ones came from a single process, PID 24628, inside a two second window.

Anyone investigating a Windows box should check this log before assuming there is no evidence. Attackers routinely disable script block logging and routinely fail to realise the disabling gets logged.

## What the script did

Eleven numbered sections, executed as SYSTEM at 2026-07-31 14:31:04. Thirteen seconds later the forged code signing certificate was issued, so this ran immediately before payload deployment.

### 1. Suppress Defender notifications

```powershell
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications
    DisableNotifications = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration
    Notification_Suppress = 1
```

So that nothing pops up in the tray while the rest happens.

### 2. Disable UAC

```powershell
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin = 0
    PromptOnSecureDesktop      = 0
```

`ConsentPromptBehaviorAdmin = 0` means administrators elevate **with no prompt at all**. Any process that asks for admin simply gets it, silently. This one persisted on my machine for two full days after I believed it was clean, because I was hunting for files and never thought to check UAC.

### 3. Disable script block logging

Covered above. The section that betrayed the whole script.

### 4. Defender path exclusions, written directly to the registry

```powershell
function aep($p){
    $k='HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
    Set-ItemProperty -Path $k -Name $p -Value 0 -Type DWord -Force
}
$drives=[System.IO.DriveInfo]::GetDrives()|Where-Object{$_.DriveType -eq 'Fixed'}|ForEach-Object{$_.Name.TrimEnd('\')}
foreach($d in $drives){aep $d}
```

Note what that does: it enumerates **every fixed drive** and excludes the entire root. Not a folder, the whole disk. It then adds the cache directories, and walks `ProfileList` to add the same paths under every user profile on the machine, skipping the built in SYSTEM, LOCAL SERVICE and NETWORK SERVICE SIDs.

It also adds the .NET Framework directories and both Temp folders, which are the entries that look plausible enough to survive a casual review. That is almost certainly deliberate. When I later found this exclusion list, the presence of legitimate looking developer paths mixed in genuinely made me hesitate before deleting the lot.

### 5. Defender process exclusions

```powershell
'InstallUtil.exe','RegAsm.exe','RegSvcs.exe','MSBuild.exe',
'AppLaunch.exe','AddInProcess.exe','aspnet_compiler.exe',
'SecurityHealthHost.exe','RuntimeHost.exe',
'lolMiner.exe','SRBMiner-MULTI.exe','miner.exe','gminer.exe'
```

The first seven are signed Microsoft .NET utilities and are the standard living off the land binaries for running arbitrary code under a trusted name. The last six are the payloads. Excluding both sets means the tooling and the malware are equally invisible.

### 6. The same exclusions again, via Add-MpPreference

Belt and braces. Writes the registry directly in sections 4 and 5, then does it again through the supported cmdlet. If one method is blocked, the other may still land.

### 7. Disable Windows Update

```powershell
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
    NoAutoUpdate                    = 1
    AUOptions                       = 1
    NoAutoRebootWithLoggedOnUsers   = 1

sc.exe config wuauserv     start= disabled
sc.exe config UsoSvc       start= disabled
sc.exe config WaaSMedicSvc start= disabled
sc.exe config bits         start= disabled
```

This is the one I want people to notice, because it has a consequence that is not obvious.

`WaaSMedicSvc` is the Windows Update self repair service, so disabling it stops Windows from fixing the other three. `bits` is Background Intelligent Transfer Service, which is what actually downloads updates **including Defender signature updates**.

For two days I kept telling the machine's owner to run `MpCmdRun.exe -SignatureUpdate` and it kept silently doing nothing, and the definitions stayed frozen at the version from the afternoon of August 1st. I assumed it was a transient failure. It was not. The update pipeline had been switched off deliberately, and every scan we ran was using stale definitions on top of a hostile exclusion list.

### 8 to 11. Firewall

```powershell
# notifications off on all three profiles
DisableNotifications = 1   (StandardProfile, PublicProfile, DomainProfile)

# catch-all, no program scope, any profile
netsh advfirewall firewall add rule name="WindowsPerf-In"  dir=in  action=allow enable=yes profile=any
netsh advfirewall firewall add rule name="WindowsPerf-Out" dir=out action=allow enable=yes profile=any

# loopback, for the local stratum proxy that hides the mining wallet
netsh advfirewall firewall add rule name="RuntimeCache" dir=in action=allow remoteip=127.0.0.1 enable=yes profile=any

# and per-exe rules for the LOLBins, both framework paths, in and out
InstallUtil.exe, RegAsm.exe, MSBuild.exe
```

`WindowsPerf-In` is an unrestricted inbound allow rule with no program and no port scope. With that in place the Windows Firewall is functionally open inbound. The name is chosen to look like a performance telemetry rule.

The `RuntimeCache` loopback rule exists to support the local stratum proxy described in the main writeup, the one that keeps the mining wallet address out of the miner's command line.

## Why this section exists

I published the first version of this writeup believing the machine was clean. It was not. I had removed every malicious **file**, every persistence entry, the LSA package, the forged certificate and four firewall rules, and I had verified all of it across several reboots. What I had not done was ask what else had been **changed**.

At the point I recovered this script, two days after the compromise, the following were all still active:

- UAC disabled, no elevation prompt
- PowerShell script block logging disabled
- Windows Update policy blocked and update services stopped
- Firewall notifications suppressed on all three profiles
- `WindowsPerf-In` and `WindowsPerf-Out` catch-all allow rules
- `RuntimeCache` loopback rule
- Twelve firewall allow rules for InstallUtil, RegAsm and MSBuild
- Defender notifications suppressed

None of that is a file. None of it shows up in a scan. All of it leaves the machine materially weaker, and all of it would have persisted indefinitely.

**Removing malware is not the same as undoing what the malware did.** If you are cleaning a Windows box, after you have deleted everything, go back and audit configuration: UAC, Windows Update, firewall rules and profiles, audit and logging policy, Defender policy, and the Group Policy hive. That is where the lasting damage is, and it is quiet.

## Undoing it

A script that reverses every section above is in [scripts/undo-sabotage.ps1](scripts/undo-sabotage.ps1). Run it elevated and reboot. Verify afterwards that `ConsentPromptBehaviorAdmin` is back to `5`, that the Windows Update policy key is gone, that the update services start, and that a signature update actually moves the version number.
