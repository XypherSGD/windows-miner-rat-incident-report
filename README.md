# My laptop was mining crypto, proxying strangers' traffic, and running a remote desktop for someone else, and Windows Defender was configured by the malware to ignore all of it

I am Xypher. On the night of August 1st into August 2nd 2026 I sat down to figure out why an app called PacketStream kept reinstalling itself on my Windows 11 laptop. I had uninstalled it more than once already. Google told me some other app was probably bringing it back, so I asked Claude (Anthropic's CLI coding agent, running with access to my shell) to help me hunt for whatever that was.

What started as "find the torrent client that bundled this junk" turned into about six hours of pulling apart a full commodity crimeware stack. By the end we had found a cryptominer with a remote control panel, an information stealer, a residential proxy backdoor, a watchdog that resurrected the whole thing, a ConnectWise ScreenConnect remote access implant, a DLL that had loaded itself into the Windows login process, a forged code signing certificate installed in my trusted root store, and a set of Group Policy settings the malware wrote specifically to hide itself from Windows Defender and from me.

This writeup is everything we found and how we found it. I am publishing it because when I searched for my symptoms I found nothing useful, and because the trick this thing used to hide from Defender is genuinely clever and I think more people should know about it.

Nothing here is theoretical. Every path, every registry key, every IP address in this document came off my machine.

---

## TL;DR for people who just want to know if they have this

Run this in an **elevated** PowerShell and see if anything comes back:

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" -Recurse -ErrorAction SilentlyContinue
Test-Path "C:\ProgramData\Microsoft\Windows\Caches\7527405F"
Test-Path "C:\ProgramData\proxies-peer"
Get-ChildItem "C:\Program Files (x86)" -Directory | Where-Object Name -match 'VC1438'
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages")."Authentication Packages"
```

That last line should print `msv1_0` and nothing else. If there is a second entry pointing at a DLL somewhere in Program Files, you have the same problem I had and you should read the whole document.

Full detection guide is in [DETECTION.md](DETECTION.md). Cleanup steps are in [REMEDIATION.md](REMEDIATION.md). Raw indicators are in [IOCS.md](IOCS.md).

---

## How it probably got in

**Read this section as a leading hypothesis, not a proven finding.** I want to be careful here because I am naming a specific project publicly and I did not do the work that would settle it.

The most likely delivery vehicle is **HyperMenu**, a cheat and mod menu for Among Us. I downloaded it on July 26th 2026 from a GitHub release:

```
https://github.com/The-HyperMenu-Team/HyperMenu/releases/tag/v4.2.1
```

I know the exact source because Windows saves it. When you download a file, Windows writes an alternate data stream called `Zone.Identifier` next to it recording where it came from. That stream was still on the zip sitting in my Downloads folder:

```powershell
Get-Content "$env:USERPROFILE\Downloads\HyperMenu-Install.zip:Zone.Identifier"
```

```
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://github.com/The-HyperMenu-Team/HyperMenu/releases/tag/v4.2.1
HostUrl=https://release-assets.githubusercontent.com/github-production-release-asset/1176130648/...
```

The zip installs a BepInEx mod loader into the Among Us folder. BepInEx itself is a legitimate, widely used Unity modding framework, and most of the files in that zip are genuine BepInEx components. The payload was a single unsigned plugin:

```
C:\Program Files (x86)\Steam\steamapps\common\Among Us\BepInEx\plugins\HyperMenu.dll
```

BepInEx loads by hijacking `winhttp.dll`. It drops its own `winhttp.dll` next to the game executable along with `doorstop_config.ini` and `.doorstop_version`, and Unity loads it on startup. That is normal BepInEx behaviour. It also means anything in the plugins folder runs inside the game process every single time you launch the game, with your user privileges, and nothing about that looks unusual to a casual observer.

Interesting detail: the config folder contained `MalumMenu.cfg` and `MalumProfile.txt`. MalumMenu is a different, publicly known Among Us cheat menu. So HyperMenu appears to be either a repackage of MalumMenu or built on top of it, with something extra bolted on.

The timeline is suggestive. The mod went in on July 26th. The first malware activity on my machine was July 31st, five days later. A delay like that is a known technique, because if a game mod fried your CPU the moment you installed it you would uninstall the mod, whereas five days later you will never connect the two.

### What I can and cannot actually prove

In favour of HyperMenu being the source:

- The `Zone.Identifier` stream confirms I downloaded it from that repo on July 26th
- It installs an unsigned DLL that executes inside the game process on every single launch
- Malware activity started five days later, and I found no other plausible vector
- It is a cheat menu, which is far and away the most common way this category of malware is distributed

Against, or at least unresolved:

- **I never disassembled `HyperMenu.dll`.** I do not know what code is in it.
- I never observed it making a network connection, writing a file, or touching the registry
- Most of the zip is genuine, unmodified BepInEx, and BepInEx itself is a legitimate modding framework
- The earliest confirmed malicious event on the machine is a Defender detection on July 31st at 07:23, `Trojan:Win32/Gracing!rfn` written to `C:\Windows\Temp\edge.exe` by `powershell.exe`. **I never determined what invoked that PowerShell process.** That is the real first observed event and its origin is still unknown to me.
- I install a lot of things. I cannot rule out another source.

So: suspicion, but not proof.

### Update: the evidence got weaker, not stronger

After first publishing this I went looking for corroboration and found the opposite. Recording it here because a writeup that only reports the evidence that fits its theory is not worth reading.

**The VirusTotal URL scan is clean.** 0 out of 92 engines on the release asset:

```
https://github.com/The-HyperMenu-Team/HyperMenu/releases/download/v4.2.1/HyperMenu-Install.zip
Detections    : 0 / 92
Last analysis : 2026-07-20 13:49:31 UTC
Status        : 200, application/octet-stream
```

Two caveats keep this from being an exoneration. It is a **URL** scan, not a file scan, so it checks whether the link is blocklisted rather than unpacking the zip or examining `HyperMenu.dll`. And the analysis date is six days before I downloaded it, so a later swap of the release asset would not show up. But it is not nothing, and it does not support my theory.

**The issue tracker shows no sign of this.** Thirty issues, going back to May 2026, and not one mentions a virus, a miner, antivirus, Defender, or anything suspicious. They are ordinary mod complaints: GUI not appearing, chat not working, crashes, feature requests. The project has 19 stars and a visibly active user base. If it were shipping a miner and a RAT in its releases you would expect at least one "my AV is going mad at this" issue, and there are none.

The counterargument holds some water: cheat users routinely disable antivirus and add exclusions before installing anything, so they may not notice or may not bother reporting. And in my case the malware wrote its own Defender exclusions. But zero reports across thirty issues is still a real data point against.

**And I destroyed the evidence.** During cleanup I deleted both `HyperMenu-Install.zip` and `HyperMenu.dll`. Correct move for cleaning the machine, but it means there is no sample left to hash or analyse. I cannot settle this, and neither can anyone reading this document from my data alone.

### Update 2: I read the whole source, and it is clean

I raised this with the project and then audited the code properly rather than reasoning from metadata. I cloned the repository and went through all 125 C# files. Findings:

| Check | Result |
|---|---|
| Hardcoded IPs, URLs, C2 endpoints | None. Every URL in the codebase is a comment linking to other open source Among Us projects or to Unity and Microsoft documentation |
| `Process.Start` | One occurrence, opening the mod's own config file in a user specified text editor |
| `WebClient`, `HttpClient`, `WebRequest`, sockets | None in source. The only matches were in the .NET SDK reference assembly list, which every project has and which means nothing |
| Registry access | None |
| `Assembly.Load` or reflective loading | None |
| Base64 or hex blobs | None |
| `VirtualAlloc`, `WriteProcessMemory`, `CreateThread` | None |
| P/Invoke | Only `user32.dll`, `gdi32.dll`, `kernel32.dll` in `StreamerUI.cs`, for window creation and bitmap drawing, consistent with the documented streamer mode feature |
| Committed binaries or scripts | None. 125 `.cs`, 5 `.yml`, 2 images, zero executables |
| `Network.cs` | Among Us RPC networking via Hazel and InnerNet. Game protocol, not internet traffic |
| `.csproj` | Four standard NuGet packages, all legitimate. The only post build step copies the compiled DLL into a local plugins folder for development |
| CI workflows | CodeQL security scanning on push, pull request and weekly, plus a manual NuGet restore helper |

There is nothing in this code that mines, downloads, persists, or contacts anything. The project also runs CodeQL security analysis on itself, which is more than most projects of its size bother with.

Additional context that all points the same way: the release asset has **1,213 downloads**, the file size on my disk matched the published asset **exactly** (33,192,144 bytes, so nothing was swapped in transit), and the issue tracker has **zero** antivirus complaints.

The only technically true caveat left is a general one that applies to any project shipping hand built binaries: the release zip was compiled on a maintainer's machine and uploaded manually rather than produced by CI, so a clean source tree does not mathematically prove the shipped binary matched it. That is a provenance gap worth closing on any project, and building releases through GitHub Actions from the public source would close it permanently. It is not evidence of wrongdoing and I am not presenting it as such.

### Where that leaves it

**I was wrong to lead with HyperMenu.** I found it because it was the most recent unusual thing I had installed, I pattern matched "game cheat" to "malware vector", and the five day gap fit a story I already believed. That is motivated reasoning, and the source audit does not support it.

To be unambiguous, since this document is public and search engines are not subtle: **I found no evidence that HyperMenu is malicious. Its source code is clean. I am not accusing this project of anything, and nobody should read this writeup as a reason to avoid it.**

The genuinely open question, and the thing I would chase if I were starting over, is what invoked the `powershell.exe` that wrote `C:\Windows\Temp\edge.exe` at 07:23 on July 31st. That is the earliest confirmed malicious event on the machine and its origin is still unknown. Everything else in this document is direct observation from my own disk and stands on its own.

If somebody with a proper analysis VM wants to pull that release apart in isolation and settle it either way, I would genuinely like to know and I will update this section. Do not do it on a machine you care about.

---

## What was actually running

### 1. The controller, disguised as a Windows component

```
C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
```

Sitting inside a real Windows directory (`C:\ProgramData\Microsoft\Windows\Caches`) under a hex folder name that looks like a cache ID. The files inside were all marked hidden and system.

It persisted four separate ways, and this is where I want to be honest about how the investigation actually went, because we did not find all four at once. We found one, declared victory, found another, declared victory again, and so on. More on that later.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    WinSysCache = C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe

HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
    WinSysCache = C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe

Scheduled tasks (all three pointing at the same exe):
    \Windows System Health
    \Windows System Health Check
    \Windows System Health Monitor

Startup folder (hidden + system attributes):
    %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\RuntimeHost.lnk
```

That `WOW6432Node` copy is the one that bit us. It is the 32 bit view of the registry. If you only check `HKCU\...\Run` and `HKLM\...\Run` like most guides tell you to, you will miss it completely, and it will restore everything on next boot. There are six Run key locations, not two.

`RuntimeHost.exe` was **digitally signed**, which is what made me look twice:

```
Subject:    CN=Dell Technologies, O=Dell Technologies, OU=WU438D, C=US
Issuer:     CN=Dell Technologies, O=Dell Technologies, OU=WU438D, C=US
Thumbprint: B60A97B26D731D549B855CE62053D9B33A08AD04
Valid from: 7/31/2026
Status:     Valid
```

Subject equals issuer, so it is self signed. It is not a real Dell certificate and it did not come from any certificate authority. But `Get-AuthenticodeSignature` reported `Valid`, and the reason it did is covered further down, because that part is worse than it looks.

### 2. The miners

`RuntimeHost.exe` kept a verbose log at `run.log` in its own folder. It downloaded miners on demand:

```
2026-08-01 16:41:39 | Download URL 1/2 attempt 1/1 from https://share-ai-123.giize.com:8443/api/tasks/payload?min...
2026-08-01 16:43:42 | Download failed: An exception occurred during a WebClient request.
2026-08-01 16:43:42 | Download URL 2/2 attempt 1/3 from https://github.com/Lolliedieb/lolMiner-releases/releases/...
2026-08-01 16:53:53 | Extracting lolminer payload
2026-08-01 16:53:53 | [Download] lolminer payload ready: C:\...\Caches\9B361726\lolminer\SecurityHealthHost.exe (12189 KB)
```

It pulls from its own panel first, and falls back to the **real GitHub release pages** for lolMiner and SRBMiner if the panel is unreachable. Then it renames the miner binary to `SecurityHealthHost.exe`, which is a real Windows filename, and stores it in another hex named folder.

The mining config, straight from the log:

```
2026-08-01 22:53:49 | [AutoStart] StartIfAutoStart: coin=PRL pool=ssl://prl.kryptex.network:8048
2026-08-01 22:53:49 | [SmartMining] Candidates for PRL: srbminer (no last-good, starting with srbminer)
2026-08-01 22:53:49 | [Pool] Selected: ssl://prl-eu.kryptex.network:8048 (115ms)
2026-08-01 22:53:50 | [StratumProxy] Started on 127.0.0.1:60479 -> ssl://prl-eu.kryptex.network:8048 [TLS]
2026-08-01 22:53:50 | [StratumProxy] Active - wallet hidden from miner args and config files
```

Read that last line again. It runs a **local stratum proxy on 127.0.0.1** so that the mining wallet address never appears in the miner's command line or config files. If you found the miner and looked at how it was launched, you would not learn who was being paid. That is a deliberate anti forensics measure and I thought it was a genuinely smart piece of engineering, in a way that annoyed me.

It only mined when I was idle:

```
2026-08-01 22:53:57 | MINER_START idle-check: userStatus=active
2026-08-01 22:53:57 | MINER_START SKIP: user is active (onlyMineWhenIdle=true)
```

So my fans never spun up while I was using the machine. This is why I had zero performance symptoms and no reason to suspect a miner.

And it took live commands from an operator:

```
2026-08-01 22:53:57 | STOP REASON: Panel sent MINER_STOP command
2026-08-01 22:53:54 | MINER_START parsed: tunnel=176.96.137.253:4041,217.216.109.4:4041 miner=auto cmd=MINER_START
```

Somebody, or some automation, was issuing start and stop instructions to my laptop in real time.

One more line that I keep coming back to:

```
Mining blocked for country: LB (mode=block)
```

`LB` is Lebanon. The operator's panel had a country filter and it was **switching mining off** for machines in Lebanon. I am in Lebanon. So the thing was sitting on my machine, fully installed, phoning home every few seconds, reporting hardware specs, and deliberately not mining because of where I am. It would have started the moment that filter changed.

### 3. The information stealer

Second log, in a different folder, `log.txt`:

```
2026-08-01 23:28:49 | [SysInfo] sent partial=True keys=16
2026-08-01 23:28:53 | [SysInfo] sent partial=True keys=17
2026-08-01 23:28:59 | [WMI] Hardware info collection started (CPU, GPU, AV, OS)
2026-08-01 23:28:59 | [WMI] Hardware info collection completed: cpu=13th Gen Intel(R) Core(TM) i7-13650HX gpu=ok av=Windows Defender
2026-08-01 23:29:19 | [SysInfo] sent partial=False keys=67
```

Data was leaving my machine every few seconds. Note `av=Windows Defender`, it was fingerprinting my antivirus. And note the periodic `keys=67` full report versus the `keys=15` to `keys=18` partials.

### 4. The residential proxy

```
C:\ProgramData\proxies-peer\peer.log
C:\ProgramData\proxies-peer\machine-id
```

```
[2026-08-01 21:16:43] [RESUMED] device=agent_dbc7c7ace856ca01 (reused saved identity)
[2026-08-01 21:16:43] [REREGISTER] refreshed identity device=agent_dbc7c7ace856ca01
[2026-08-01 21:16:44] [CONNECTED] device=agent_dbc7c7ace856ca01 relay=wss://relay.proxies.sx
[2026-08-01 21:16:44] [ACK] relay confirmed connection
[2026-08-01 21:17:06] STATS tunnels=0 errs=0 up=0 down=0
```

My machine was registered as a proxy exit node with a persistent device ID, connected over WebSocket to `relay.proxies.sx`. This is the same category of thing as PacketStream, which is what sent me down this hole in the first place. Other people's traffic exits through your home connection, from your IP address. If somebody uses that for something illegal, it comes back to you.

### 5. The watchdog

```
C:\ProgramData\HostsServices\
    HostsServices.exe               (21 MB)
    psclient.exe                    (21 MB, same size, likely identical)
    pslauncher.exe
    PacketStreamInstaller-HS.exe
    start.vbs
    watchdog.vbs
    HostsServices-setup.log
```

This is the piece that answered my original question. `PacketStreamInstaller-HS.exe` is what kept putting PacketStream back every time I uninstalled it. `watchdog.vbs` relaunched things if they died. It ran via:

```
HKCU\...\Run  HostsServices = wscript.exe //B //Nologo "C:\ProgramData\HostsServices\start.vbs"
Scheduled tasks: \HostsServices and \HostsServicesWatchdog
Startup folder: PacketStream.lnk -> C:\ProgramData\HostsServices\pslauncher.exe
```

Worth noting `wscript.exe //B //Nologo`. Using the Windows Script Host to launch a VBS file means the thing in your Run key is a signed Microsoft binary, not a suspicious executable.

### 6. ScreenConnect, which is the part that actually scared me

```
C:\Program Files (x86)\Microsoft.VC1438.MFC\ScreenConnect.ClientService.exe
```

Installed as a Windows service named `VCRuntimeHelper_x86`. Both the folder name and the service name are engineered to look like a Microsoft Visual C++ redistributable, which is the single most boring thing you can find in Program Files and the last thing anyone investigates.

ConnectWise ScreenConnect is legitimate commercial remote support software. It is signed by a real company, it is used by real IT departments, and antivirus products generally do not flag it because flagging it would break thousands of businesses. That is exactly why criminals love it.

I caught it because I asked for a list of every established outbound connection with its owning process, and this was in the list:

```
Remote                Proc                          Path
198.23.185.136:8041   ScreenConnect.ClientService   C:\Program Files (x86)\Microsoft.VC1438.MFC\...
```

A live, established connection. At that moment I disconnected my laptop from the internet.

The full service command line contained the connection parameters:

```
"?e=Access&y=Guest&h=update.tap-vpns.top&p=8041&s=9976cbe7-b97c-4648-9ad8-285d53336a6e&k=BgIAAACkAABSU0Ex...&c=livelywallpaper&c=&c=&c=&c=&c=&c=&c="
```

Breaking that down:

- `e=Access` is the ScreenConnect unattended access role, meaning no prompt, no visible consent, connect whenever you want
- `h=update.tap-vpns.top` is the relay hostname, dressed up to look like a VPN update server
- `p=8041` is the port
- `s=9976cbe7-b97c-4648-9ad8-285d53336a6e` is the session GUID identifying my machine to the operator
- `k=` is the base64 public key blob for the relay
- `c=livelywallpaper` and seven more empty `c=` fields are ScreenConnect custom properties, which are free text labels the operator types in when generating an installer

That `c=livelywallpaper` label briefly made me think Lively Wallpaper (a legitimate open source app I have installed) was the source. It was not. I checked every binary in that install and it is a clean, complete, normal Lively Wallpaper 2.2.1.0 by rocksdanister. The `c=` value is just whatever the attacker typed into a box. It tells you what they named the campaign, not what delivered it. Do not let a label send you after the wrong thing, which is what almost happened to me.

**On whether anyone actually watched my screen:** I want to be precise, because this is the thing everybody asks. I have proof that the client service was installed, that it was configured for unattended access, and that it held an established connection to the relay. I do **not** have session logs proving a human connected and viewed my desktop. ScreenConnect does not leave that on the client side in a way I could recover after the fact. So the honest statement is: someone had the ability to view and control this machine at will, and the channel was open. Whether they used it, I cannot prove either way. I am treating it as though they did.

### 7. The LSA authentication package, which is the worst thing in this document

Inside that same folder:

```
C:\Program Files (x86)\Microsoft.VC1438.MFC\ScreenConnect.WindowsAuthenticationPackage.dll
```

And in the registry:

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    Authentication Packages = { msv1_0, C:\Program Files (x86)\Microsoft.VC1438.MFC\ScreenConnect.WindowsAuthenticationPackage.dll }
```

`msv1_0` is the normal Windows one and belongs there. The second entry does not.

Authentication packages are loaded by the Local Security Authority, `lsass.exe`, at boot, before you log in, running as SYSTEM. `lsass.exe` is the process that handles every credential on the machine. Code loaded there can observe authentication. This is a documented Windows extensibility point, it exists for legitimate single sign on products, and it is also a well known credential theft technique.

This file refused to die. Even as an administrator, even after taking ownership with `takeown`, even after `icacls` granting full control, even with `rmdir /s /q`, it returned access denied. Its ACL was completely normal, no deny rules, Administrators had full control on paper. It was simply loaded into a protected process and Windows was not going to let go of it.

The fix was to edit the registry value first, remove only the malicious path while keeping `msv1_0`, reboot so LSA reloads without it, and then delete the file. It came off without complaint after the reboot.

If you find this on your machine, treat every password ever typed on it as compromised. I did.

### 8. The forged root certificate

```
Store:      Cert:\LocalMachine\Root  (Trusted Root Certification Authorities)
Subject:    CN=Dell Technologies, O=Dell Technologies, OU=WU438D, C=US
Thumbprint: B60A97B26D731D549B855CE62053D9B33A08AD04
Valid to:   7/31/2027
```

This is why `RuntimeHost.exe` showed as validly signed. The attacker generated a self signed certificate impersonating Dell, installed it into my machine's trusted root store, and signed their payloads with the matching private key. From that point on Windows considered anything they signed to be from a trusted publisher.

This is a re-infection enabler and it outlives the malware. If you clean every file and leave this certificate behind, the next payload they drop still passes signature checks. Check your root store. On a normal consumer machine there is no reason for a self signed certificate to be sitting in there.

### 9. Firewall rules

```
RuntimeHost           Inbound   Allow   C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
RuntimeHost           Outbound  Allow   C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
SecurityHealthHost    Inbound   Allow   C:\...\Caches\7527405F\Content.IE5\CBADF215\SecurityHealthHost.exe
SecurityHealthHost    Outbound  Allow   C:\...\Caches\7527405F\Content.IE5\CBADF215\SecurityHealthHost.exe
```

Pre authorised network access, waiting for the payloads to come back. That `Content.IE5\CBADF215\` path also revealed a payload location I had not found any other way, so it is worth dumping your firewall rules even if you think you are done.

---

## The part I actually want people to read: how it hid from Defender

This is the bit that cost us hours and it is the most useful thing in this document.

All night, Windows Defender reported a list of exclusions that covered every single folder the malware lived in:

```
C:\Program Files (x86)\
C:\ProgramData\49681505\
C:\ProgramData\Microsoft\Windows\Caches\7527405F\
C:\ProgramData\Microsoft\Windows\Caches\7527405F\B8C9\
C:\ProgramData\Microsoft\Windows\Caches\7527405F\Content.IE5\
C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
C:\ProgramData\proxies-peer\
C:\Users\<USER>\AppData\Local\Microsoft\Windows\8B86CBC\
C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\7527405F\
C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\9B361726\
C:\Users\<USER>\AppData\Local\proxies-peer\
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Caches\7527405F\
```

Plus a process exclusion list:

```
InstallUtil.exe, RegAsm.exe, RegSvcs.exe, MSBuild.exe, AppLaunch.exe,
AddInProcess.exe, aspnet_compiler.exe, SecurityHealthHost.exe,
RuntimeHost.exe, lolMiner.exe, SRBMiner-MULTI.exe, miner.exe,
gminer.exe, miniZ.exe
```

Those first seven are not malware. They are legitimate Microsoft .NET utilities. They are also the standard "living off the land" binaries that attackers use to execute arbitrary code under a trusted process name. Excluding them, plus the `.NET Framework` directories they live in, plus the whole of `C:\Program Files (x86)\`, creates a permanent blind spot to run anything in.

And these exclusions would not delete. Not through the Windows Security GUI, where the Remove button was greyed out. Not through `Remove-MpPreference` in an elevated PowerShell, which cheerfully reported success and changed nothing. Not after restarting the Defender service. Not after a reboot. We deleted them at least four separate times across the night.

I made things harder by half believing an explanation that turned out to be wrong. At one point Claude concluded the entries were stale cached data, because the local enforcement key at `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` genuinely only contained seven benign default entries, and told me it was cosmetic and safe to ignore. It was not cosmetic. That was a wrong call and if I had accepted it the machine would still be infected.

The actual answer was here:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions
    HideExclusionsFromLocalAdmins = 1
    DisableLocalAdminMerge        = 1

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths
    (all the malicious paths)

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes
    (all the malicious process names)
```

The malware wrote **Group Policy** settings. Both of those two values are real, documented Microsoft Defender enterprise policy settings, and they were turned against me:

- `HideExclusionsFromLocalAdmins = 1` does exactly what the name says. It hides the exclusion list from local administrators. This is a real feature intended for corporate environments where IT does not want staff to see what is excluded. It is why the Remove button was greyed out, and it is why an unelevated process querying that registry path sees nothing at all while an elevated one sees the whole list. We spent a long time confused by exactly that inconsistency.

- `DisableLocalAdminMerge = 1` makes the policy list authoritative and stops local settings from merging in. Group Policy exclusions always win over local ones. So `Remove-MpPreference` would delete the local copy, return success, and then `Get-MpPreference` would re-merge the policy list straight back on top. Every removal was real. Every removal was also pointless.

This also explains the `This setting is managed by your administrator` banner on the Tamper Protection toggle, on a personal laptop with no employer and no IT department. And there was a `Policy Manager` key in there too.

My machine is not domain joined, not Azure AD joined, and not MDM enrolled. We verified all three with `dsregcmd /status`. On a machine like that, there is **no legitimate reason for anything to exist under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`**. If you find that key populated on a home machine, that is your answer.

Deleting `Exclusions` and `Policy Manager`, then running `gpupdate /force` and restarting the Defender service, cleared the list instantly and permanently. First thing all night that stuck on the first try.

### The consequence nobody thinks about

Every scan I ran before that point was blindfolded. Including the Microsoft Defender Offline scan, the one that boots before Windows and is supposed to be the trustworthy last word. It honours the configured exclusion list. So it dutifully skipped `Caches\7527405F`, `proxies-peer`, `49681505`, and all of `Program Files (x86)`, which is to say it skipped every single folder that mattered, and came back clean while all of it was sitting right there on disk.

If you take one thing from this document: **clear the policy exclusions before you trust any scan result.** A clean scan means nothing until you have verified what the scanner was allowed to look at.

Related: Malwarebytes on this machine would not launch. It threw "unexpected error" every time. I never fully proved why, but a security product failing to start on a box where the attacker has Group Policy level control over the security stack is not something I would call a coincidence.

---

## Attacker infrastructure

| Indicator | Detail |
|---|---|
| `198.23.185.136:8041` | ScreenConnect relay. AS63025 NOHAVPS LLC, Draper, Utah, US |
| `update.tap-vpns.top` | Hostname for the above, dressed as a VPN update server |
| `176.96.137.253:4041` | Miner tunnel. AS58212 dataforest GmbH, Frankfurt, Germany |
| `217.216.109.4:4041` | Miner tunnel. AS141995 Contabo Asia, Singapore. rDNS `vmi3227383.contaboserver.net` |
| `share-ai-123.giize.com:8443` | Miner payload and task panel. `giize.com` is free dynamic DNS (FreeDNS / Afraid.org) |
| `wss://relay.proxies.sx` | Residential proxy relay, WebSocket |
| `prl.kryptex.network:8048` | Kryptex mining pool, plus `prl-eu`, `prl-sg`, `prl-hk`, `prl-ru`, `prl-us`, `prl-br`, `prl-ae` regional endpoints |
| Session GUID | `9976cbe7-b97c-4648-9ad8-285d53336a6e` |
| Proxy device ID | `agent_dbc7c7ace856ca01` |
| Cert thumbprint | `B60A97B26D731D549B855CE62053D9B33A08AD04` |

The mined coin was PRL (Parallel) via Kryptex. The wallet address is not recoverable from my machine because of the local stratum proxy described earlier.

---

## Attribution, and why I changed my mind

I live in Lebanon. When I saw a remote access tool with a live connection and a component sitting inside the Windows login process, my first instinct was that this might be targeted surveillance, and I said so out loud. Plenty of people here would jump to the same conclusion and I do not think that instinct is unreasonable given the region.

The evidence does not support it, and I would rather publish something correct than something dramatic.

- It **mines cryptocurrency**. Intelligence operations do not mine PRL on your GPU. That is a monetisation scheme.
- The operator's own panel **blocked mining in Lebanon**. `Mining blocked for country: LB (mode=block)`. An operation targeting Lebanese citizens does not configure itself to stand down in Lebanon. That reads like an operator skipping regions with bad power costs or low hardware value.
- The C2 ran on **free dynamic DNS**, `giize.com`. Nobody running a state programme hosts their infrastructure on a free dyndns account.
- The servers are **cheap commodity VPS** from NOHAVPS, dataforest and Contabo. Not dedicated infrastructure, just rented boxes.
- Delivery was a **public GitHub release of an Among Us cheat**. That is spray and pray. It hits whoever installs it, anywhere on earth. There is nothing about it that selects for me, my country, or my work.
- Every single component is **off the shelf**: ScreenConnect, PacketStream, lolMiner, SRBMiner, BepInEx, a self signed cert. No custom implants, no zero days, nothing you cannot download or buy.

This is a financially motivated operator monetising infected machines three ways at once: mining the GPU, renting the bandwidth as a residential proxy, and keeping remote access in hand for whatever else comes up. That is the accurate finding.

I am including this section because the pull toward a scary explanation is strong when you are three hours into finding things in `lsass.exe` at two in the morning, and because a writeup that gets attribution wrong gives readers a reason to distrust the parts that are right.

---

## Honest notes on how the investigation actually went

I am including this because most incident writeups present a clean narrative and that is not what happened, and I think the messy version is more useful.

We declared the machine clean at least four times before it actually was. Each time, something we had not checked turned out to be holding a piece of it:

1. Cleaned PacketStream and BitTorrent. Missed `HostsServices` entirely.
2. Cleaned `HostsServices`. Found `RuntimeHost` and the miners afterwards.
3. Cleaned those. The exclusions kept coming back and we misdiagnosed it as a display bug.
4. A deeper audit found the `WOW6432Node` Run key we had never checked, because we had only looked at two of the six Run key locations.
5. A network connection audit found ScreenConnect, hours after the point where we thought it was over.
6. Certificate and firewall checks, which almost did not happen, found the forged root cert and four allow rules.
7. Only right at the end did the Group Policy exclusions surface, and only because an elevated script could see keys that an unelevated one could not.

Things that repeatedly wasted time:

- Running admin-required commands in a non elevated session and reading the empty output as "nothing there". This happened more than once and it directly caused the wrong "there is no Exclusions key" conclusion. If a security check returns nothing, verify your privilege level before you believe it.
- Trusting a clean scan result without checking what the scanner was permitted to scan.
- Assuming that because a removal command reported success, the removal happened.

What actually broke the case open was checking things nobody thinks to check: every established network connection with its owning process, the trusted root certificate store, the firewall rule list, and the Group Policy hive.

---

## What I did afterwards

Beyond removing everything:

- Changed every important password from my phone on cellular data, not from the laptop and not on my home network. Email first, since it is the reset path for everything else, then banking, then Steam, Discord and GitHub. Anything typed on that laptop between July 31st and August 2nd should be considered known to somebody else.
- Turned Tamper Protection back on and confirmed it stays on.
- Confirmed there are **no non Microsoft kernel drivers** running on the machine. This was the single most reassuring result of the night. Everything found lived in userland or in LSA, which is why it was reachable and removable at all. Had there been a kernel rootkit, none of this cleanup would have been trustworthy and a wipe would have been mandatory.
- Reinstalled Among Us from scratch through Steam.
- Stopped installing game cheats and mods from random GitHub repos, which is the actual root cause and the only one of these that would have prevented the whole thing.

A full wipe and clean Windows install is still the only way to be completely certain after something reaches LSA. I understand that. I chose to keep the install because no kernel level component was found and every persistence mechanism was accounted for. If you are in the same position and the machine holds anything valuable, wipe it. That is the safer call and I will not pretend otherwise.

---

## The thing I got most wrong: removing the malware is not the same as undoing it

Two days after I thought this machine was clean, I went looking in the PowerShell operational event log and found the attacker's entire setup script sitting there in full. It ran as SYSTEM at 14:31:04 on July 31st, thirteen seconds before the forged certificate was issued.

It survived because of a mistake on their side. Section 3 of the script disables PowerShell script block logging, but PowerShell logs a script block when it **compiles** it, before any line runs. So it logged itself in the act of switching logging off.

The script has eleven numbered sections. I had cleaned up three of them. At the moment I recovered it, all of the following were **still active on a machine I had declared clean**:

- **UAC disabled.** `ConsentPromptBehaviorAdmin = 0`, meaning admin processes elevate silently with no prompt
- **PowerShell script block logging disabled**
- **Windows Update disabled**, both by policy and by stopping `wuauserv`, `UsoSvc`, `WaaSMedicSvc` and `bits`
- **A catch-all inbound firewall allow rule** named `WindowsPerf-In`, no program scope, no port scope, which leaves the firewall functionally open inbound
- A matching outbound catch-all, a loopback rule, and twelve allow rules for `InstallUtil.exe`, `RegAsm.exe` and `MSBuild.exe`
- Firewall notifications suppressed on all three profiles
- Defender notifications suppressed

None of that is a file. None of it appears in any scan. All of it would have stayed there forever.

It also explains something that had been quietly wasting our time for two days. Disabling `bits` kills the transfer service that downloads **Defender signature updates**, and disabling `WaaSMedicSvc` stops Windows from repairing that. I kept telling the owner to run `MpCmdRun.exe -SignatureUpdate`, it kept silently doing nothing, and the definitions stayed frozen. I assumed a transient glitch. It was sabotage, and it meant every scan we ran used stale definitions on top of a hostile exclusion list.

**If you are cleaning a Windows machine: after you have deleted everything, go back and audit what was changed.** UAC, Windows Update, firewall rules and profiles, logging and audit policy, Defender policy, the Group Policy hive. That is where the durable damage is, and it is completely silent.

Full breakdown, the recovered script, and how to pull it off your own machine: [ATTACKER-SCRIPT.md](ATTACKER-SCRIPT.md).

---

## Files in this repo

- [ATTACKER-SCRIPT.md](ATTACKER-SCRIPT.md) - the attacker's setup script recovered in full, and how to recover it yourself
- [DETECTION.md](DETECTION.md) - how to check whether you have this
- [REMEDIATION.md](REMEDIATION.md) - step by step cleanup, in the order that works
- [IOCS.md](IOCS.md) - plain list of indicators for blocklists and threat feeds
- [TIMELINE.md](TIMELINE.md) - full chronology with timestamps
- [scripts/audit.ps1](scripts/audit.ps1) - read only audit of every surface described here
- [scripts/undo-sabotage.ps1](scripts/undo-sabotage.ps1) - reverses the configuration changes above

---

## Credit and method

The analysis was done by me working with Claude, Anthropic's CLI agent, with shell access to the affected machine. It ran the enumeration, read the logs, spotted the patterns and wrote the cleanup scripts. I ran the elevated commands, pushed back when something did not add up, and found the Microsoft Get Help article that pointed at the Group Policy exclusions key, which turned out to be the answer after we had dismissed that location. Neither of us would have got there alone. The wrong turns described above are recorded accurately, including the ones that were mine.

Everything in this document came off one laptop on one night. If it helps one person find the `Policies\Microsoft\Windows Defender\Exclusions` key faster than I did, it was worth writing.

Questions or corrections, open an issue.

Xypher
August 2026
