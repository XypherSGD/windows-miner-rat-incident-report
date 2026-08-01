# Reverses every hardening change made by the attacker's setup script
# (recovered from PowerShell event log, PID 24628, 2026-07-31 14:31:04).
# Run ELEVATED.

Write-Output "################ 1. Re-enable UAC ################"
$uac = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty $uac -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord -Force
Set-ItemProperty $uac -Name PromptOnSecureDesktop      -Value 1 -Type DWord -Force
Set-ItemProperty $uac -Name EnableLUA                  -Value 1 -Type DWord -Force
Get-ItemProperty $uac | Select-Object ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, EnableLUA

Write-Output "`n################ 2. Re-enable PowerShell script block logging ################"
$sbl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Set-ItemProperty $sbl -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force
Get-ItemProperty $sbl | Select-Object EnableScriptBlockLogging

Write-Output "`n################ 3. Restore Windows Update ################"
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
foreach ($s in @(@('wuauserv','Manual'), @('UsoSvc','Automatic'), @('WaaSMedicSvc','Manual'), @('bits','Automatic'))) {
    try {
        Set-Service -Name $s[0] -StartupType $s[1] -ErrorAction Stop
        Write-Output "  $($s[0]) -> $($s[1])"
    } catch { Write-Output "  $($s[0]) FAILED: $($_.Exception.Message)" }
}
Start-Service wuauserv -ErrorAction SilentlyContinue
Start-Service bits -ErrorAction SilentlyContinue
Get-Service wuauserv,UsoSvc,WaaSMedicSvc,bits | Select-Object Name, Status, StartType

Write-Output "`n################ 4. Remove attacker firewall rules ################"
foreach ($n in @('WindowsPerf-In','WindowsPerf-Out','RuntimeCache','RuntimeCache-v6','InstallUtil','RegAsm','MSBuild')) {
    $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
    if ($r) { $r | ForEach-Object { Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue; Write-Output "  removed: $($_.DisplayName) [$($_.Direction)]" } }
}

Write-Output "`n################ 5. Restore firewall notifications ################"
@('StandardProfile','PublicProfile','DomainProfile') | ForEach-Object {
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$_" -Name DisableNotifications -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
}
Write-Output "  done"

Write-Output "`n################ 6. Restore Defender notifications ################"
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Recurse -Force -ErrorAction SilentlyContinue
Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -Name Notification_Suppress -Force -ErrorAction SilentlyContinue
Write-Output "  done"

Write-Output "`n################ 7. Verify firewall is actually on ################"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

Write-Output "`n################ 8. Now signature update should work ################"
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate
Get-MpComputerStatus | Select-Object AntivirusSignatureVersion, AntivirusSignatureLastUpdated

Write-Output "`n################ FINAL VERIFY ################"
"UAC ConsentPromptBehaviorAdmin : $((Get-ItemProperty $uac).ConsentPromptBehaviorAdmin)   (5 = normal)"
"ScriptBlockLogging             : $((Get-ItemProperty $sbl -EA SilentlyContinue).EnableScriptBlockLogging)   (1 = on)"
"WU policy key                  : $(if(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'){'STILL PRESENT'}else{'removed'})"
"Attacker FW rules remaining    : $((Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.DisplayName -in 'WindowsPerf-In','WindowsPerf-Out','RuntimeCache','InstallUtil','RegAsm','MSBuild' }).Count)"
Write-Output "################ DONE - REBOOT AFTER THIS ################"
