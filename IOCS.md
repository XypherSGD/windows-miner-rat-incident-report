# Indicators of Compromise

Everything below was observed directly on the affected machine (Windows 11 Home 26100, Intel i7-13650HX). Timestamps are local, UTC+3.

Paths use `<USER>` where the local Windows username appeared.

---

## Network

### IP addresses

| IP | Port | Role | ASN / Provider | Location |
|---|---|---|---|---|
| `198.23.185.136` | 8041 | ScreenConnect relay (live established session observed) | AS63025 NOHAVPS LLC | Draper, Utah, US |
| `176.96.137.253` | 4041 | Miner tunnel endpoint | AS58212 dataforest GmbH | Frankfurt am Main, Germany |
| `217.216.109.4` | 4041 | Miner tunnel endpoint | AS141995 Contabo Asia Private Limited | Singapore |

`217.216.109.4` reverse DNS: `vmi3227383.contaboserver.net`

### Domains

| Domain | Port | Role | Notes |
|---|---|---|---|
| `update.tap-vpns.top` | 8041 | ScreenConnect relay hostname | Named to look like a VPN update endpoint |
| `share-ai-123.giize.com` | 8443 | Miner payload host and task panel | `giize.com` is free dynamic DNS (FreeDNS / Afraid.org) |
| `relay.proxies.sx` | wss (443) | Residential proxy relay, WebSocket | |

### Mining pools contacted

Legitimate pool infrastructure, listed for completeness. Presence of these in outbound traffic on a machine that does not mine is itself a signal.

```
ssl://prl.kryptex.network:8048
ssl://prl-eu.kryptex.network:8048
ssl://prl-sg.kryptex.network:8048
ssl://prl-hk.kryptex.network:8048
ssl://prl-ru.kryptex.network:8048
ssl://prl-us.kryptex.network:8048
ssl://prl-br.kryptex.network:8048
ssl://prl-ae.kryptex.network:8048
```

Coin: PRL (Parallel). Wallet address not recoverable, see note on the local stratum proxy in README.

### Payload fallback sources

The dropper pulled miners from its own panel first, then fell back to the genuine upstream GitHub releases. These are legitimate projects being abused as a CDN, not malicious repos.

```
https://github.com/Lolliedieb/lolMiner-releases/releases/...
https://github.com/doktor83/SRBMiner-Multi/releases/...
```

### Identifiers

```
ScreenConnect session GUID : 9976cbe7-b97c-4648-9ad8-285d53336a6e
Proxy device ID            : agent_dbc7c7ace856ca01
ScreenConnect label        : c=livelywallpaper
```

---

## Filesystem

### Directories

```
C:\ProgramData\Microsoft\Windows\Caches\7527405F\
C:\ProgramData\Microsoft\Windows\Caches\7527405F\B8C9\
C:\ProgramData\Microsoft\Windows\Caches\7527405F\Content.IE5\
C:\ProgramData\Microsoft\Windows\Caches\7527405F\Content.IE5\CBADF215\
C:\ProgramData\49681505\
C:\ProgramData\proxies-peer\
C:\ProgramData\HostsServices\
C:\Program Files (x86)\Microsoft.VC1438.MFC\
C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\9B361726\
C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\rt-8B86CBC\
C:\Users\<USER>\AppData\Local\Microsoft\Windows\8B86CBC\
C:\Users\<USER>\AppData\Local\proxies-peer\
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Caches\7527405F\
C:\Users\<USER>\AppData\Roaming\packetstream\
```

Note the naming convention: eight character uppercase hex folder names placed inside real Windows cache directories. `Content.IE5` is a genuine legacy Internet Explorer cache folder name, reused here for camouflage.

### Files

```
C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe          (1,031,224 bytes)
C:\ProgramData\Microsoft\Windows\Caches\7527405F\run.log
C:\ProgramData\Microsoft\Windows\Caches\7527405F\c.dat
C:\ProgramData\Microsoft\Windows\Caches\7527405F\p.dat
C:\ProgramData\Microsoft\Windows\Caches\7527405F\sp.dat
C:\ProgramData\Microsoft\Windows\Caches\7527405F\connection_type.txt
C:\ProgramData\Microsoft\Windows\Caches\7527405F\last_start_message.txt
C:\ProgramData\Microsoft\Windows\Caches\7527405F\last_start_result.txt
C:\ProgramData\Microsoft\Windows\Caches\7527405F\last_stop_reason.txt
C:\ProgramData\Microsoft\Windows\Caches\7527405F\Content.IE5\CBADF215\SecurityHealthHost.exe

C:\ProgramData\49681505\ccv.exe                                           (387,584 bytes)
C:\ProgramData\49681505\mzcv.exe                                          (103,424 bytes)

C:\ProgramData\proxies-peer\peer.log
C:\ProgramData\proxies-peer\machine-id

C:\ProgramData\HostsServices\HostsServices.exe                            (21,150,768 bytes)
C:\ProgramData\HostsServices\psclient.exe                                 (21,150,768 bytes)
C:\ProgramData\HostsServices\pslauncher.exe                               (3,482,920 bytes)
C:\ProgramData\HostsServices\PacketStreamInstaller-HS.exe                 (7,513,336 bytes)
C:\ProgramData\HostsServices\start.vbs                                    (855 bytes)
C:\ProgramData\HostsServices\watchdog.vbs                                 (450 bytes)
C:\ProgramData\HostsServices\HostsServices-setup.log

C:\Program Files (x86)\Microsoft.VC1438.MFC\ScreenConnect.ClientService.exe
C:\Program Files (x86)\Microsoft.VC1438.MFC\ScreenConnect.WindowsAuthenticationPackage.dll

C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\9B361726\lolminer\SecurityHealthHost.exe   (12,482,256 bytes)
C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\9B361726\.b\lolminer\m.dat                 (12,482,256 bytes)
C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\9B361726\srbminer\lolMiner.exe             (12,482,256 bytes)
C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\9B361726\srbminer\lolMinerGUI.exe

C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Caches\7527405F\log.txt
C:\Users\<USER>\AppData\Roaming\packetstream\psclient.exe                 (21,150,768 bytes)

C:\Windows\Temp\HostsServices.exe                                         (7,696,384 bytes)
C:\Windows\Temp\PacketStreamInstaller-HS.exe                              (7,513,336 bytes)
```

Most files carried Hidden + System attributes (`-a-hs-`).

### Delivery vehicle

```
C:\Users\<USER>\Downloads\HyperMenu-Install.zip                           (33,192,144 bytes)
C:\Program Files (x86)\Steam\steamapps\common\Among Us\BepInEx\plugins\HyperMenu.dll   (unsigned)
C:\Program Files (x86)\Steam\steamapps\common\Among Us\winhttp.dll
C:\Program Files (x86)\Steam\steamapps\common\Among Us\doorstop_config.ini
C:\Program Files (x86)\Steam\steamapps\common\Among Us\.doorstop_version
```

Download origin from the `Zone.Identifier` alternate data stream:

```
https://github.com/The-HyperMenu-Team/HyperMenu/releases/tag/v4.2.1
```

Config files present alongside it referenced **MalumMenu**, a separately known Among Us cheat, suggesting HyperMenu is a repackage or derivative:

```
BepInEx\config\MalumMenu.cfg
BepInEx\config\MalumProfile.txt
```

---

## Registry

### Run keys

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    WinSysCache    = C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
    HostsServices  = wscript.exe //B //Nologo "C:\ProgramData\HostsServices\start.vbs"

HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
    WinSysCache    = C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
```

The `WOW6432Node` entry is the 32 bit registry view and is missed by most cleanup guides. There are six Run key locations that need checking:

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

### LSA authentication package

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    Authentication Packages (REG_MULTI_SZ) =
        msv1_0
        C:\Program Files (x86)\Microsoft.VC1438.MFC\ScreenConnect.WindowsAuthenticationPackage.dll
```

Expected clean value on a normal machine is `msv1_0` alone.

### Group Policy tampering

This is the key finding. On a machine that is not domain joined, not Azure AD joined and not MDM enrolled, none of this should exist.

```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions
    HideExclusionsFromLocalAdmins (REG_DWORD) = 1
    DisableLocalAdminMerge        (REG_DWORD) = 1

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths
    C:\Program Files (x86)\                                             = 0
    C:\ProgramData\49681505\                                            = 0
    C:\ProgramData\Microsoft\Windows\Caches\7527405F\                   = 0
    C:\ProgramData\Microsoft\Windows\Caches\7527405F\B8C9\              = 0
    C:\ProgramData\Microsoft\Windows\Caches\7527405F\Content.IE5\       = 0
    C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe    = 0
    C:\ProgramData\proxies-peer\                                        = 0
    C:\Users\<USER>\AppData\Local\Microsoft\Windows\8B86CBC\            = 0
    C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\7527405F\    = 0
    C:\Users\<USER>\AppData\Local\Microsoft\Windows\Caches\9B361726\    = 0
    C:\Users\<USER>\AppData\Local\proxies-peer\                         = 0
    C:\Users\<USER>\AppData\Local\Temp\                                 = 0
    C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Caches\7527405F\  = 0
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\                    = 0
    C:\Windows\Microsoft.NET\Framework\v4.0.30319\                      = 0
    C:\Windows\Temp\                                                    = 0

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes
    InstallUtil.exe        = 0
    RegAsm.exe             = 0
    RegSvcs.exe            = 0
    MSBuild.exe            = 0
    AppLaunch.exe          = 0
    AddInProcess.exe       = 0
    aspnet_compiler.exe    = 0
    SecurityHealthHost.exe = 0
    RuntimeHost.exe        = 0
    lolMiner.exe           = 0
    SRBMiner-MULTI.exe     = 0
    miner.exe              = 0
    gminer.exe             = 0
    miniZ.exe              = 0

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager
    (present, associated with the Tamper Protection "managed by your administrator" state)
```

Note that the .NET Framework directories and Temp folders were mixed into the malicious list. Those look plausible and are commonly added by developer tooling, which is presumably the point. Do not use "some of these look legitimate" as a reason to leave the key alone.

The first seven process exclusions are Microsoft signed .NET utilities commonly abused as LOLBins for arbitrary code execution:

```
InstallUtil.exe, RegAsm.exe, RegSvcs.exe, MSBuild.exe,
AppLaunch.exe, AddInProcess.exe, aspnet_compiler.exe
```

---

## Scheduled tasks

```
\Windows System Health           -> C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
\Windows System Health Check     -> C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
\Windows System Health Monitor   -> C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
\HostsServices                   -> wscript.exe "C:\ProgramData\HostsServices\start.vbs"
\HostsServicesWatchdog           -> wscript.exe "C:\ProgramData\HostsServices\watchdog.vbs"
```

---

## Services

```
Name         : VCRuntimeHelper_x86
Binary       : "C:\Program Files (x86)\Microsoft.VC1438.MFC\ScreenConnect.ClientService.exe"
Arguments    : "?e=Access&y=Guest&h=update.tap-vpns.top&p=8041&s=9976cbe7-b97c-4648-9ad8-285d53336a6e&k=BgIAAACkAABSU0Ex...&c=livelywallpaper&c=&c=&c=&c=&c=&c=&c="
```

Parameter meanings:

| Field | Value | Meaning |
|---|---|---|
| `e` | `Access` | Unattended access role. No consent prompt shown to the user |
| `y` | `Guest` | Client type |
| `h` | `update.tap-vpns.top` | Relay hostname |
| `p` | `8041` | Relay port |
| `s` | `9976cbe7-...` | Session GUID identifying this machine to the operator |
| `k` | base64 blob | Relay public key |
| `c` | `livelywallpaper` | Operator supplied custom label, plus seven empty ones |

---

## Startup folder

```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\RuntimeHost.lnk    (Hidden + System)
    -> C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe

%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\PacketStream.lnk
    -> C:\ProgramData\HostsServices\pslauncher.exe
```

---

## Firewall rules

```
RuntimeHost          Inbound   Allow   C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
RuntimeHost          Outbound  Allow   C:\ProgramData\Microsoft\Windows\Caches\7527405F\RuntimeHost.exe
SecurityHealthHost   Inbound   Allow   C:\...\Caches\7527405F\Content.IE5\CBADF215\SecurityHealthHost.exe
SecurityHealthHost   Outbound  Allow   C:\...\Caches\7527405F\Content.IE5\CBADF215\SecurityHealthHost.exe
```

---

## Certificate

Installed into `Cert:\LocalMachine\Root` (Trusted Root Certification Authorities):

```
Subject     : CN=Dell Technologies, O=Dell Technologies, OU=WU438D, C=US
Issuer      : CN=Dell Technologies, O=Dell Technologies, OU=WU438D, C=US
Serial      : 2471EECAEA694DA248D2A43CDBBF60F2
Thumbprint  : B60A97B26D731D549B855CE62053D9B33A08AD04
Not Before  : 7/31/2026 2:31:17 PM
Not After   : 7/31/2027 2:41:17 PM
```

Self signed (subject equals issuer). Used to sign `RuntimeHost.exe` so that `Get-AuthenticodeSignature` returns `Valid`.

---

## Detections raised by Windows Defender

Only one, and it predates the main investigation:

```
ThreatName           : Trojan:Win32/Gracing!rfn
ThreatID             : 2147921953
Severity             : 5
Detected             : 7/31/2026 7:23:42 AM
Remediated           : 7/31/2026 7:24:07 AM
Process              : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Resource             : file:_C:\Windows\Temp\edge.exe
```

Defender caught one dropper on July 31st and quarantined it. Everything described in this repo was installed on the same machine on the same day and was never detected, because by then the Group Policy exclusions were in place.

---

## What was NOT found

Recorded because negative results matter for scoping.

- No non Microsoft kernel drivers running. No rootkit at driver level.
- No WMI event subscription persistence.
- No Image File Execution Options debugger hijacks.
- No `AppInit_DLLs` or `AppCertDlls` entries.
- No COM hijacks under `HKCU\Software\Classes\CLSID` outside standard paths.
- No PowerShell profile scripts.
- No Winsock LSP, netsh helper, print monitor or time provider tampering.
- `BootExecute` and `KnownDLLs` unmodified.
- Hosts file, proxy settings and DNS settings unmodified.
- No malicious browser extensions.
- Machine not domain joined, not Azure AD joined, not MDM enrolled (`dsregcmd /status`).
