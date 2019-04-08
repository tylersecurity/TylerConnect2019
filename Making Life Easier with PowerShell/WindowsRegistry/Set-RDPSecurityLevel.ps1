[CmdletBinding()]
param (
    [parameter(Mandatory=$false)][int]$SecurityLayer=2,
    [parameter(Mandatory=$false)][int]$MinEncryptionLevel=3
    )

 <#
.SYNOPSIS
Set minimum security settings for the Remote Desktop Protocol
.AUTHOR
Joel Stuedle
.COMPANY
Tyler Technologies, Inc.
.DESCRIPTION
#####SecurityLayer#####
1 - SSL/TLS 1.0 will be used for RDP 
2 - Negotiate The most secure layer that is supported by the client will be used (Default)
3 - Native RDP encryption will be used to protect RDP Sessions.

#####MinEncryptionLevel#####
1 - Low, Data sent from the client to the server is encrypted using 56-bit encryption.  Data sent from the server to the client is not encrypted 
2 - Client compatible (Default) - Encrypts client / server communication at the maximum key strength supported by the client.
3 - High - Encrypts client / server communication using 128-bit encryption.
4 - FIPS-Compliant (NOT Recommended without through testing) - All client / server communication is encrypted and decrypted with the Federal Information Processing Standard (FIPS) encryption algorithms.
 .EXAMPLE
Set-RDPSecurity
.PARAMETER SecurityLayer
Sets the SecurityLayer DWord value in the Windows Registry HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
.PARAMETER MinEncryptionLevel
Sets the MinEncryptionLevel DWord value in the Windows Registry HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
 #>
try {
    $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', $true).SetValue("SecurityLayer",2,"DWord")
    $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', $true).SetValue("MinEncryptionLevel",3,"DWord")
    Write-Host -ForegroundColor Green "RDP Minimum Security and Encryption requirements set."
    } catch {
        throw "Failed to set subkey. Access denied or not found."
    }