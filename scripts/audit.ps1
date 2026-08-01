# audit.ps1
# Read only. Changes nothing. Run in an ELEVATED PowerShell.
#
# Several of these checks return empty output when run unelevated, which reads
# as "clean" and is not. Confirm elevation before trusting any empty result.

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "NOT ELEVATED. Results will be incomplete and misleading. Re-run as Administrator."
    Start-Sleep 3
}

function Section($t) { "`r`n" + ("=" * 70); "== $t"; ("=" * 70) }

Section "0. Machine management status (should all be NO on a home PC)"
dsregcmd /status | Select-String "AzureAdJoined|EnterpriseJoined|DomainJoined"

Section "1. Defender GROUP POLICY hive - the important one"
"On an unmanaged machine this should be empty or only 'UX Configuration'."
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    "KEY: $($_.Name)"
    (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).PSObject.Properties |
        Where-Object Name -notlike 'PS*' |
        ForEach-Object { "      $($_.Name) = $($_.Value -join ', ')" }
}

Section "2. LSA authentication packages (expect: msv1_0 only)"
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages" -ErrorAction SilentlyContinue)."Authentication Packages"
"-- Security / Notification packages --"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages","Notification Packages" -ErrorAction SilentlyContinue |
    Select-Object "Security Packages","Notification Packages"

Section "3. Defender effective config"
"ExclusionPath:"; (Get-MpPreference).ExclusionPath
"ExclusionProcess:"; (Get-MpPreference).ExclusionProcess
Get-MpComputerStatus | Select-Object IsTamperProtected, RealTimeProtectionEnabled, AntivirusEnabled, AMServiceEnabled

Section "4. All six Run / RunOnce locations"
@(
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
 "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
 "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
) | ForEach-Object {
    "--- $_"
    Get-ItemProperty $_ -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | Format-List | Out-String
}

Section "5. Startup folders (Force reveals hidden+system shortcuts)"
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue
Get-ChildItem "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\StartUp" -Force -ErrorAction SilentlyContinue

Section "6. Scheduled tasks with actions"
Get-ScheduledTask | ForEach-Object {
    $t = $_
    $t.Actions | ForEach-Object {
        [PSCustomObject]@{ Task=$t.TaskName; Path=$t.TaskPath; State=$t.State; Execute=$_.Execute; Args=$_.Arguments }
    }
} | Where-Object { $_.Execute -notmatch '^%windir%' } | Format-Table -AutoSize | Out-String -Width 300

Section "7. Services outside Windows / Program Files"
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -and $_.PathName -notmatch '^"?C:\\Windows\\|^"?C:\\Program Files' } |
    Select-Object Name, DisplayName, PathName, State, StartMode | Format-List

Section "7b. Remote access tooling (any of these you did not install is a problem)"
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -match 'ScreenConnect|ConnectWise|AnyDesk|TeamViewer|Atera|Splashtop|RustDesk|Supremo|LogMeIn|GoToAssist|NinjaRMM|Syncro|VC1438' } |
    Select-Object Name, PathName | Format-List

Section "8. Established outbound connections with owning process"
"Account for EVERY line. This is the check that found the RAT."
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notmatch '^127\.|^::1|^0\.0\.0\.0' } |
    ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{ Remote="$($_.RemoteAddress):$($_.RemotePort)"; Proc=$p.ProcessName; Path=$p.Path }
    } | Sort-Object Proc | Format-Table -AutoSize | Out-String -Width 200

Section "9. Running processes outside Windows / Program Files, with signature"
Get-Process | Where-Object { $_.Path -and $_.Path -notmatch '^C:\\Windows\\|^C:\\Program Files' } | ForEach-Object {
    $s = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Name=$_.ProcessName; Sig=$s.Status; Signer=($s.SignerCertificate.Subject -replace '^CN=([^,]+).*','$1'); Path=$_.Path }
} | Sort-Object Name -Unique | Format-Table -AutoSize | Out-String -Width 200

Section "10. Running kernel drivers not signed by Microsoft (rootkit surface)"
"Empty output here is the result you want."
Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | ForEach-Object {
    $p = $_.PathName -replace '\\\?\?\\',''
    if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
        $s = Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue
        $subj = $s.SignerCertificate.Subject -replace '^CN=([^,]+).*','$1'
        if ($s.Status -ne 'Valid' -or $subj -notmatch 'Microsoft') {
            [PSCustomObject]@{ Name=$_.Name; Status=$s.Status; Signer=$subj }
        }
    }
} | Format-Table -AutoSize

Section "11. Self signed certificates in Trusted Root"
"Look for company names with no business being a CA, and recent issue dates."
Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $_.Issuer } |
    Select-Object Subject, NotBefore, NotAfter, Thumbprint |
    Sort-Object NotBefore -Descending | Select-Object -First 25 | Format-List
"-- Trusted Publisher store --"
Get-ChildItem Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue | Select-Object Subject, NotAfter

Section "12. Firewall rules for programs outside Windows / Program Files"
Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | ForEach-Object {
    $af = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    if ($af.Program -and $af.Program -ne 'Any' -and $af.Program -notmatch '^C:\\Windows|^C:\\Program Files|^%') {
        [PSCustomObject]@{ Name=$_.DisplayName; Dir=$_.Direction; Action=$_.Action; Program=$af.Program }
    }
} | Format-Table -AutoSize | Out-String -Width 200

Section "13. Other persistence surfaces (all should be empty / default)"
"-- WMI event subscriptions --"
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, CommandLineTemplate
"-- Image File Execution Options debuggers --"
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object {
    $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($d) { "$($_.PSChildName) -> $d" }
}
"-- AppInit_DLLs / AppCertDlls --"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue | Select-Object AppInit_DLLs, LoadAppInit_DLLs
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -ErrorAction SilentlyContinue
"-- Winlogon --"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select-Object Shell, Userinit
"-- BootExecute (expect: autocheck autochk *) --"
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name BootExecute -ErrorAction SilentlyContinue).BootExecute
"-- PowerShell profiles (expect: none) --"
@($PROFILE.AllUsersAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.CurrentUserAllHosts,$PROFILE.CurrentUserCurrentHost) |
    ForEach-Object { if (Test-Path $_) { "EXISTS: $_"; Get-Content $_ } }
"-- COM hijacks in HKCU outside standard paths --"
Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
    $d = (Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
    if ($d -and $d -notmatch '^C:\\Windows|^C:\\Program Files|OneDrive|^mscoree') { "$($_.PSChildName) -> $d" }
}
"-- netsh helpers / print monitors / time providers --"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Netsh" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS*
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" -ErrorAction SilentlyContinue | ForEach-Object {
    $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver; if ($d) { "$($_.PSChildName) -> $d" } }
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders" -ErrorAction SilentlyContinue | ForEach-Object {
    "$($_.PSChildName) -> $((Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DllName)" }

Section "14. Network config integrity"
Get-Content "$env:WINDIR\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue | Select-Object ProxyEnable, ProxyServer, AutoConfigURL
netsh winhttp show proxy

Section "15. Known IOC paths from this incident"
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
 "$env:APPDATA\packetstream"
) | ForEach-Object { "{0,-70} {1}" -f $_, (Test-Path $_) }

Section "15b. Generic pattern: hex named folders in Windows cache dirs"
@("C:\ProgramData","C:\ProgramData\Microsoft\Windows\Caches",
  "$env:LOCALAPPDATA\Microsoft\Windows\Caches","$env:APPDATA\Microsoft\Windows\Caches") | ForEach-Object {
    Get-ChildItem $_ -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9A-F]{6,10}$' -or $_.Name -match '^rt-[0-9A-F]+$' } |
        Select-Object FullName, CreationTime
}

Section "16. Defender detection history"
Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending |
    Select-Object -First 25 ThreatID, ProcessName, InitialDetectionTime, Resources | Format-List
Get-MpThreat -ErrorAction SilentlyContinue | Select-Object ThreatName, SeverityID, CurrentStatus | Format-List

Section "DONE"
