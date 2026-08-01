# Trying to find the entry vector, and failing honestly

This document covers the forensic pass I ran two days after the compromise to work out how the machine was breached, what each artifact is good for, and why it did not give me the answer. I am writing up the failure in detail because "here is how I found it" writeups are common and "here is what I tried, and why it did not work" writeups are not, and the second kind would have saved me time.

## What I was trying to answer

Two events prove the attacker held SYSTEM:

```
2026-07-31 07:23:42   powershell.exe (NT AUTHORITY\SYSTEM) drops C:\Windows\Temp\edge.exe
                      Defender detects Trojan:Win32/Gracing!rfn, quarantines it
                      (quarantine record: 2026-07-31 04:24:07 UTC)

2026-07-31 14:31:04   the setup script runs under SID S-1-5-18 (SYSTEM)
                      13 seconds later the forged certificate is issued
```

So the question is not "which program did I run", it is "what gave someone SYSTEM before 07:23 on July 31st".

## The artifacts, and what each is actually good for

### BAM (Background Activity Moderator)

```
HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
```

Each value is an executable path, and the first 8 bytes of the data are a FILETIME of its **last** execution. Requires elevation to read.

```powershell
$bam = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>"
(Get-Item $bam).Property | ForEach-Object {
    $v = (Get-ItemProperty $bam -Name $_).$_
    if ($v -is [byte[]] -and $v.Length -ge 8) {
        [PSCustomObject]@{ Time = [DateTime]::FromFileTime([BitConverter]::ToInt64($v,0)); Exe = $_ }
    }
} | Sort-Object Time
```

This is the best single "what ran and when" artifact on a Windows machine, and it is per user, so filtering on `S-1-5-18` separates SYSTEM activity from yours.

### Prefetch

```
C:\Windows\Prefetch\*.pf
```

Windows writes one file per executable, and the file's `LastWriteTime` is the **last** time that program ran. Requires elevation to list. Filenames are `NAME.EXE-<hash>.pf`, where the hash covers the full path and command line, so the same binary invoked differently produces separate entries.

### UserAssist

```
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```

GUI launches only, names ROT13 encoded, with a run counter and last run time. Readable without elevation. On my machine it held almost nothing useful, which appears to be normal on Windows 11 rather than evidence of tampering.

### Others worth pulling

- `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` (ShimCache), 292,988 bytes on my machine, needs a dedicated parser
- `HKCU:\Software\Classes\Local Settings\...\MuiCache`, programs that have been run
- `C:\ProgramData\Microsoft\Windows\WER\ReportArchive`, crash reports, which incidentally prove a program ran
- `C:\Windows\System32\Tasks\*`, scheduled task XML, with useful creation timestamps

## Why none of it answered the question

**BAM and Prefetch store only the *last* execution time.**

That single property destroyed the timeline. Every tool the attacker used on July 31st ran again on August 1st, so the July 31st timestamps were simply overwritten:

```
RUNTIMEHOST.EXE-4460D980.pf      2026-08-01 22:53:34
WSCRIPT.EXE-3FF4D889.pf          2026-08-01 22:53:36
INSTALLUTIL.EXE-9953E407.pf      2026-08-01 22:53:44
PSLAUNCHER.EXE-40D3ABD3.pf       2026-08-01 22:54:14
PSCLIENT.EXE-2503C9F9.pf         2026-08-01 22:55:05
SCHTASKS.EXE-8B6144A9.pf         2026-08-01 20:14:38
NETSH.EXE-8174DA63.pf            2026-08-01 21:08:27
```

All of those certainly executed on July 31st as well. The evidence of that is gone.

The same applies to BAM, which shows a clean gap across the entire compromise window:

```
2026-07-30 07:36:53   FirasNet.exe
   ... nothing ...
2026-07-31 20:49:40   FirasLightsV2.exe
```

The machine was powered on throughout that period, confirmed by event log 6005 at 2026-07-30 11:41 and the power off at 2026-07-31 17:01. The gap is not a shutdown and it is not anti forensics. It is just last-write semantics doing what they do.

**Lesson:** BAM and Prefetch are excellent for "has this ever run" and "when did it last run". They are close to useless for reconstructing a specific past window on a machine that has kept running since. If you are investigating an incident, image the disk or export these artifacts **before** you keep using the box. I did not, and I lost the timeline.

## Two things the artifacts did establish

### InstallUtil.exe genuinely executed

```
INSTALLUTIL.EXE-9953E407.pf      2026-08-01 22:53:44
```

`InstallUtil.exe` is a signed Microsoft .NET utility and a classic living off the land binary for executing managed code under a trusted process name. It appears in the attacker's Defender process exclusion list, and this proves it was not just excluded defensively, it was actually used.

If you find `InstallUtil.exe`, `RegAsm.exe`, `RegSvcs.exe` or `MSBuild.exe` in a prefetch listing on a machine where nobody develops .NET software, treat it as a finding.

### ScreenConnect ran its interactive client

```
SCREENCONNECT.WINDOWSCLIENT.E-FB849E7D.pf      2026-08-01 23:46:19
```

This one matters. `ScreenConnect.ClientService.exe` is the background service, and it will sit connected to the relay doing nothing. `ScreenConnect.WindowsClient.exe` is the component involved in an actual session.

Earlier in this writeup I said I could prove the remote access channel existed but could not prove anyone used it. This shifts that. It is not conclusive, because the service can spawn the client for reasons other than an operator connecting, but it is meaningfully more than "the channel was open". And the timestamp, 23:46 on August 1st, falls inside the window when I was actively investigating the machine.

I am not going to claim more than the artifact supports. Take it as: the interactive component ran, and I cannot account for why.

## The applications I checked, and what I found

I install a lot of games, mods and utilities, and the obvious move was to work through them. Results, so nobody repeats the work:

| Application | Installed | Last executed | Signature findings | Verdict |
|---|---|---|---|---|
| HyperMenu (Among Us cheat) | 2026-07-26 | n/a, plugin runs in game | Full source audit of 125 files, clean. 0/92 on VirusTotal | **Cleared.** See main writeup |
| EZFN Launcher (Fortnite private server) | 2026-07-27 | 2026-07-28 22:00 | Launcher and installer unsigned. `startEZFN.exe` validly signed by EasyAntiCheat Oy | No persistence, no files touched after install, nothing linking it to July 31st |
| TLauncher (Minecraft) | 2026-07-08 | 2026-07-28 20:44 | All Java `.jar`, which cannot carry Authenticode signatures | Nothing found. Separately a cracked launcher with a poor reputation |
| Counter-Strike 1.6 (Unikov repack) | 2026-07-04 | 2026-07-28 20:44 | Mixed. Original files validly signed by Valve, modified client files signed by NextClient, several unsigned | Nothing found. It is a modified repack, which is its own risk |
| Meetion Combine (peripheral driver) | 2026-07-07 | 2026-07-27 23:34 | Everything unsigned, ships `AutoUpdate.exe` and `libcurl.dll` | Nothing found. Unsigned vendor software with an updater is standing attack surface |
| Anghami (music) | 2026-07-17 | 2026-07-26 15:36 | Unsigned Electron app with a Squirrel updater | Nothing found. Legitimate mainstream service, sloppy packaging |
| Lively Wallpaper | 2026-07-17 | 2026-07-27 22:40 | Unsigned, open source | **Cleared.** Verified every binary |

**None of them executed during the compromise window.** The last execution for every candidate is July 28th, three days before. That does not clear them as droppers, since a dropper can install something that fires later, but I found no persistence belonging to any of them.

Two general points worth more than the table:

**Unsigned is not the same as malicious.** Most of the list is unsigned. Electron apps, open source projects, Java software and small hardware vendors routinely ship without code signing certificates because they cost money. Signature status is a useful sorting signal and a terrible verdict on its own. I nearly convinced myself twice on this basis.

**Pip generated console scripts will flood this kind of search.** My unsigned executable sweep returned dozens of hits under `AppData\Roaming\Python\Python39\Scripts` (`tqdm.exe`, `idna.exe`, `normalizer.exe` and so on). Those are wrapper stubs `pip` generates on install, they are unsigned by design, and they are noise. Filter them out early.

## Where the entry vector stands

Unresolved.

I know the attacker had SYSTEM by 07:23 on July 31st. I know what they did with it, in complete detail, because they logged their own setup script for me. I do not know how they got it, and the artifacts that could have told me were overwritten by two more days of ordinary use before I thought to look.

Things I would do differently, in order of how much they would have helped:

1. **Export BAM, Prefetch, ShimCache, Amcache and the event logs immediately**, before continuing to use the machine. Once you know you are compromised, the box is evidence. Every hour of continued use erases some of it.
2. **Enable process creation auditing before you need it.** Security event 4688 with command line capture would have answered this outright. It is off by default and it is the single most valuable logging change you can make on a Windows machine.
3. **Do not delete samples during cleanup.** I destroyed `HyperMenu-Install.zip` and `HyperMenu.dll` while cleaning, which removed my own ability to settle the question either way. Move suspicious files to a password protected archive on external media instead.

The lack of an answer does not weaken anything else in this repository. Everything else is direct observation from disk and registry, and it stands regardless of how the first foothold was obtained.
