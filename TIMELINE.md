# Timeline

All times local, UTC+3 (Beirut). Reconstructed from file timestamps, the malware's own log files, Windows Defender detection history, and registry key write times.

---

## Before the incident

**July 17, 2026** - Lively Wallpaper 2.2.1.0 installed. Recorded here only because the ScreenConnect client carried a `c=livelywallpaper` label, which briefly made it a suspect. It was verified clean and is not involved. Also the date on the earliest `PacketStreamInstaller-HS.exe` file found on disk (04:34).

**July 24, 2026** - Malwarebytes 5.6.3.277 installed.

**July 26, 2026, 15:33** - `HyperMenu-Install.zip` downloaded from `github.com/The-HyperMenu-Team/HyperMenu/releases/tag/v4.2.1`. 33 MB.

**July 26, 2026, 15:35 to 15:39** - Files extracted into the Among Us folder. BepInEx loader, `winhttp.dll`, `doorstop_config.ini`, and `BepInEx\plugins\HyperMenu.dll`.

**July 26, 2026, 15:36** - Second wave of files written into the Among Us `dotnet` folder.

**July 26, 2026, 20:57** - Last modification inside the Among Us folder before the gap.

Then nothing for five days.

---

## Day one: the machine is taken

**July 31, 2026, 07:23:42** - Windows Defender detects `Trojan:Win32/Gracing!rfn` at `C:\Windows\Temp\edge.exe`, written by `powershell.exe` running as `NT AUTHORITY\SYSTEM`. Remediated successfully at 07:24:07.

This is the earliest confirmed malicious event. Note two things. First, the dropping process was already running as SYSTEM, so privilege escalation had already happened by this point or the invoking mechanism was itself privileged. Second, **what invoked that PowerShell was never determined.** This remains the largest gap in the investigation.

**July 31, 2026, 14:31:17** - The forged "Dell Technologies" certificate is issued (`Not Before` timestamp). Ten minutes later at 14:41:17 it is installed and the payload signed with it.

**July 31, 2026, 14:40:20** - Hidden payload directories created:
```
%LOCALAPPDATA%\Microsoft\Windows\Caches\9B361726
%LOCALAPPDATA%\Microsoft\Windows\Caches\rt-8B86CBC
```

**July 31, 2026, 14:41** - `RuntimeHost.exe` written to `C:\ProgramData\Microsoft\Windows\Caches\7527405F`. Status files (`last_start_message.txt`, `last_start_result.txt`, `last_stop_reason.txt`) created alongside it. The hidden `RuntimeHost.lnk` startup shortcut is created at 14:40.

At some point in this window, though I could not pin the exact time, the Group Policy exclusions were written and Tamper Protection was disabled. Everything after this point happens inside a blind spot.

---

## Day two: the machine is monetised

**August 1, 2026, 16:41:39** - `RuntimeHost.exe` attempts to download a miner from its control panel at `https://share-ai-123.giize.com:8443/api/tasks/payload`. Fails after two minutes.

**August 1, 2026, 16:43:42** - Falls back to the genuine lolMiner GitHub release page.

**August 1, 2026, 16:53:53** - lolMiner extracted and renamed:
```
%LOCALAPPDATA%\Microsoft\Windows\Caches\9B361726\lolminer\SecurityHealthHost.exe   (12,189 KB)
```

**August 1, 2026, 20:14:37** - `HostsServices.exe` written to `C:\Windows\Temp`.

**August 1, 2026, 20:15** - The `C:\ProgramData\HostsServices` folder is fully populated: `HostsServices.exe`, `psclient.exe`, `pslauncher.exe`, `PacketStreamInstaller-HS.exe`, `start.vbs`, `watchdog.vbs`. This is the component responsible for reinstalling PacketStream every time I removed it.

**August 1, 2026, 21:16:40 to 21:17:09** - Proxy client activity in `peer.log`:
```
21:16:40  [CLOSED]     websocket: close 4002: Invalid token
21:16:43  [RESUMED]    device=agent_dbc7c7ace856ca01 (reused saved identity)
21:16:43  [REREGISTER] refreshed identity device=agent_dbc7c7ace856ca01
21:16:44  [CONNECTED]  device=agent_dbc7c7ace856ca01 relay=wss://relay.proxies.sx
21:16:44  [ACK]        relay confirmed connection
21:17:06  STATS tunnels=0 errs=0 up=0 down=0
21:17:09  Stopping. Goodbye.
```
The token expired, the client re-registered itself, reconnected, and carried on.

**August 1, 2026, 22:53:49** - Mining session begins. Pool latency tested across eight Kryptex regional endpoints, `prl-eu` selected at 115 ms. Local stratum proxy started on `127.0.0.1:60479` specifically so the wallet address never appears in the miner's arguments or config.

**August 1, 2026, 22:53:54** - Operator command received:
```
MINER_START parsed: tunnel=176.96.137.253:4041,217.216.109.4:4041 miner=auto cmd=MINER_START coin=PRL
```

**August 1, 2026, 22:53:57** - Mining is skipped because I was at the keyboard:
```
MINER_START idle-check: userStatus=active
MINER_START SKIP: user is active (onlyMineWhenIdle=true)
```
Then, seconds later:
```
STOP REASON: Panel sent MINER_STOP command
```

**August 1, 2026, 23:03:07** - A miner download fails and the malware correctly diagnoses why:
```
Extracted zip: no miner exe found; tried: SRBMiner-MULTI.exe
Download failed (AV/quarantine, will re-probe storage + exclusions): Miner executable not found inside downloaded zip. (possible AV quarantine)
```
It knows about antivirus quarantine and it re-probes its own exclusions when it happens.

---

## The investigation

**August 1, 2026, around 22:00** - I start looking into why PacketStream keeps coming back. I ask Claude for help finding the app that is bundling it.

**22:15** - BitTorrent found in the installed programs list. Assumed to be the culprit. Its files turn out to already be gone, only a stale registry entry remains.

**22:30** - `PacketStream.lnk` found in the Startup folder pointing at `C:\ProgramData\HostsServices\pslauncher.exe`. First sight of `HostsServices`.

**22:45** - `C:\ProgramData\HostsServices` contents enumerated. `PacketStreamInstaller-HS.exe` and `watchdog.vbs` make it clear this is not a bundling accident. Two scheduled tasks and a Run key found.

**23:02** - I delete the `packetstream` folder. It reappears. Processes `psclient.exe` and `pslauncher.exe` are found running.

**23:29** - `RuntimeHost.exe` discovered via the `WinSysCache` Run key. Its `run.log` is read. This is the moment it stops being adware and becomes a miner with a control panel.

**23:53** - First reboot. `HostsServices` and its tasks are gone but two payload folders regenerate.

**August 2, 2026, 00:15** - Defender exclusions found covering every malware folder. First attempt to remove them. They come back.

**00:40** - Defender Offline scan run. Comes back clean. This is misleading and it takes another two hours to understand why.

**01:10** - I am told the exclusions are probably a display cache artifact and are cosmetic. This is wrong, and if I had accepted it the machine would still be infected.

**01:30** - Deep audit finds the `WinSysCache` entry in `HKLM\SOFTWARE\WOW6432Node\...\Run`, a location not previously checked. This is what had been restoring things across reboots.

**01:45** - I ask whether the `HyperMenu-Install.zip` still sitting in my Downloads could be the source. The Among Us folder is examined and the BepInEx plugin found.

**02:00** - A full audit of established network connections finds `ScreenConnect.ClientService.exe` running from `C:\Program Files (x86)\Microsoft.VC1438.MFC` with a live connection to `198.23.185.136:8041`. I disconnect the laptop from the internet.

**02:15** - `ScreenConnect.WindowsAuthenticationPackage.dll` found registered in the LSA `Authentication Packages` key. This is the low point of the night.

**02:30** - LSA registry value corrected to `msv1_0` only. Reboot. The DLL finally deletes.

**02:50** - Certificate store audit finds the forged "Dell Technologies" root certificate. Firewall audit finds four allow rules for the payloads, one of which reveals a payload path not found any other way.

**03:10** - Kernel driver audit comes back completely clean. No rootkit. This is the best news of the night and it is what made cleaning, rather than wiping, a defensible choice.

**03:20** - I find a Microsoft Get Help article suggesting the exclusions might be under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`. That location had already been checked and reported empty, so it was nearly dismissed a second time.

**03:30** - Run from an elevated session, the policy hive turns out to contain `Exclusions` and `Policy Manager` keys that were invisible to the unelevated check, because the malware had set `HideExclusionsFromLocalAdmins = 1`. Everything that had been confusing all night is explained in one screen of output.

**03:35** - Policy keys deleted, `gpupdate /force`, Defender service restarted. The exclusion list clears instantly and stays clear. Tamper Protection stops reporting that it is managed by an administrator.

---

## Total

From first confirmed compromise (July 31, 07:23) to full remediation (August 2, 03:35) is approximately **44 hours**.

From the mod being installed (July 26, 15:33) to full remediation is approximately **7 days**.

The machine spent that entire period mining on idle, proxying traffic, reporting hardware telemetry every few seconds, and holding an open remote access channel, with Windows Defender running, enabled, real time protection on, reporting the machine as healthy the whole way through.
