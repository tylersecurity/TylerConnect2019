##
#Windows Defender Registry Settings
##
#https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/configure-real-time-protection-windows-defender-antivirus

# Enable Block at first sight
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 2 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 3 -PropertyType DWord -Force

# Enable Behavior Monitoring
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWord -Force

# Enable On-Access Protection
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWord -Force

# Enable Process Scanning
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWord -Force

# Enable bi-direction file scaninng
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "RealTimeScanDirection" -Value 0 -PropertyType DWord -Force

# Enable Network Protection
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -name "DisableIntrusionPreventionSystem" -Value 0 -PropertyType DWord -Force

# Disable Watson Events
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericReports" -Value 1 -PropertyType DWord -Force

# Enable Check for updates before scan
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "CheckForSignaturesBeforeRunningScan" -Value 1 -PropertyType DWord -Force

# Enable Scan Archive files
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableArchiveScanning" -Value 0 -PropertyType DWord -Force

# Enable email scan
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0 -PropertyType DWord -Force

# Enable Heuristics
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DissbleHeuristics" -Value 0 -PropertyType DWord -Force

# Enable Packed executable scanning
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisablePackedExeScanning" -Value 0 -PropertyType DWord -Force

# Enable Removable Drive Scanning
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0 -PropertyType DWord -Force

# Enable Reparse Point Scanning
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableReparsePointScanning" -Value 0 -PropertyType DWord -Force

# Setting default scan to quick
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "ScanParameters" -Value 0 -PropertyType DWord -Force

# Setting update fallback order
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "FallbackOrder" -Value "MMPC|MicrosoftUpdateServer" -PropertyType String -Force

# Enable Real-item Definiton Updates
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "RealTimeSigatureDelivery" -Value 1 -PropertyType DWord -Force

# Setting update interval to every hour
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "SignatureUpdateInterval" -Value 1 -PropertyType DWord -Force

# Setting antimalware service to normal priority startup
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "AllowFastServiceStartup" -Value 1 -PropertyType DWord -Force

# Allow service to remain running always
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 1 -PropertyType DWord -Force

# Enable Antivirus and antispyware
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 -PropertyType DWord -Force

# Enable PUA detection
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePUS" -Value 1 -PropertyType DWord -Force

# Enable Exploit Guard Network Protection
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" | Out-Null
}
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -PropertyType DWord -Force

# Enable Controlled Folder Access
Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable Early Launch AntiMalware
if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" | Out-Null
}
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 1 -PropertyType DWord -Force

# Set Threat action to quarantine
Set-MpPreference -HighThreatDefaultAction Quarantine
Set-MpPreference -LowThreatDefaultAction Quarantine
Set-MpPreference -ModerateThreatDefaultAction Quarantine
Set-MpPreference -UnknownThreatDefaultAction Quarantine

# Enable Extended cloud check
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpBafsExtendedTimeout" -Value 50 -PropertyType DWord -Force

# Set Defender Cloud Protection Level
# Note: This may detect legitimate files, however, you have the options to unblock or dispute this action

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpCloudBlockLevel" -Value 4 -PropertyType DWord -Force

# Enable Defender ASR Rules

Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled