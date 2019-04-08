#Requires -Version 5.1
[CmdletBinding()]
 <#
 .SYNOPSIS
 Set minimum security settings for Windows Server 2k8R2-2k16
 .DESCRIPTION
 This script has been tested on Server 2008R2 SP1, Server 2012 R2, and Server 2016. The server should receive an "A+" on Qualys SSL Labs scans after running this hardening script.
	-Set RDP Minimum Security levels to be FIPS compliant
	-Set SchUseStrongCrypto for all .NET Applications
	-Sets Windows Protocol/Cipher Settings
		-TLS 1.2 will be the only protocol enabled after the script runs
	-Globally enables HTTP to HTTPS rewrite in IIS
	-Globally enables HTTP Strict Transport Security (HSTS) in IIS
NOTE: Windows Server 2008 R2 ships with Windows Management Framework (WMF) 2.0, WMF must be updated to a minimum version 5.1 before running this script.
********************
CAUTION: Always test any and all scripts in a test environment first. Some legacy applications may not be able to communicate with upstream or downstream servers or services that do not explicitly support TLS 1.2. 
********************
  .EXAMPLE
 .\Harden-WindowsServer.ps1 -RunNow
 .EXAMPLE
 Import-Module .\Harden-WindowsServer.ps1
 Harden-WindowsServer
 .PARAMETER RunNow
 Execute the Script Now
 #>
param (
    [parameter(Mandatory=$false)][Switch]$RunNow
    )
 
function Harden-WindowsServer() {
try {
    $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', $true).SetValue("SecurityLayer",2,"DWord")
    $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp', $true).SetValue("MinEncryptionLevel",3,"DWord")
    Write-Host -ForegroundColor Green "Minimum Security and Encryption requirements enforced for RDP Connections"
    } catch {
        throw "Failed to set subkey. Access denied or not found."
    }
 
write-host -ForegroundColor Yellow "`n`n********************.NET SchUseStrongCrypto********************"
try {
    $key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v2.0.50727', $true).SetValue("SchUseStrongCrypto",1,"DWord")
    Write-Host "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\"
    Write-Host "DWord: SchUseStrongCrypto value set to 1"
     
    $key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727', $true).SetValue("SchUseStrongCrypto",1,"DWord")
    Write-Host "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\"
    Write-Host "DWord: SchUseStrongCrypto value set to 1"
     
     
    $key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v4.0.30319', $true).SetValue("SchUseStrongCrypto",1,"DWord")
    Write-Host "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\"
    Write-Host "DWord: SchUseStrongCrypto value set to 1"
     
    $key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319', $true).SetValue("SchUseStrongCrypto",1,"DWord")
    Write-Host "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    Write-Host "DWord: SchUseStrongCrypto value set to 1"
} catch {
    throw "Failed to set subkey. Access denied or not found (Is PowerShell being run as Administrator?)."
}
 
 
write-host -ForegroundColor Yellow "`n`n********************.NET SystemDefaultTlsVersions********************"
try {
    $key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v2.0.50727', $true).SetValue("SystemDefaultTlsVersions",1,"DWord")
    Write-Host "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\"
    Write-Host "DWord: SystemDefaultTlsVersions value set to 1"
     
    $key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727', $true).SetValue("SystemDefaultTlsVersions",1,"DWord")
    Write-Host "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\"
    Write-Host "DWord: SystemDefaultTlsVersions value set to 1"
     
     
    $key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Microsoft\.NETFramework\v4.0.30319', $true).SetValue("SystemDefaultTlsVersions",1,"DWord")
    Write-Host "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\"
    Write-Host "DWord: SystemDefaultTlsVersions value set to 1"
     
    $key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319', $true).SetValue("SystemDefaultTlsVersions",1,"DWord")
    Write-Host "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    Write-Host "DWord: SystemDefaultTlsVersions value set to 1"
} catch {
    throw "Failed to set subkey. Access denied or not found (Is PowerShell being run as Administrator?)."
}
 
 
 
 
write-host -ForegroundColor Yellow "`n`n********************Cipher Suites********************"
$secureCiphers = @(
  'AES 128/128',
  'AES 256/256',
  'Triple DES 168'
)
 
Foreach ($secureCipher in $secureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
  $key.SetValue('Enabled',0xFFFFFFFF, 'DWord')
  $key.close()
  Write-Host -ForegroundColor DarkGreen "Cipher $secureCipher has been enabled."
}
 
$insecureCiphers = @(
  'DES 56/56',
  'NULL',
  'RC2 128/128',
  'RC2 40/128',
  'RC2 56/128',
  'RC4 40/128',
  'RC4 56/128',
  'RC4 64/128',
  'RC4 128/128'
)
Foreach ($insecureCipher in $insecureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
  $key.SetValue('Enabled', 0, 'DWord')
  $key.close()
  Write-Host -ForegroundColor DarkRed "Cipher $insecureCipher has been disabled."
}
  
write-host -ForegroundColor Yellow "`n`n********************Hashing Algorithms********************"
 
$SecureHashes = @(
    'SHA',
    'SHA256',
    'SHA384',
    'SHA512'
)
 
$InsecureHashes = @(
    'MD5'
)
 
Foreach ($hash in $SecureHashes) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($hash)
  $key.SetValue('Enabled',0XFFFFFFFF, 'DWord')
  $key.close()
  Write-Host -ForegroundColor DarkGreen "Hash $hash has been enabled."
}
 
Foreach ($hash in $InsecureHashes) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($hash)
  $key.SetValue('Enabled', 0, 'DWord')
  $key.close()
  Write-Host -ForegroundColor DarkRed "Hash $hash has been disabled."
}
 
 
write-host -ForegroundColor Yellow "`n`n********************Key Exchange Algorithms********************"
 
$KeyExchangeAlgorithms = @(
    'Diffie-Hellman',
    'ECDH',
    'PKCS'
)
 
Foreach ($KeyExchangeAlgorithm in $KeyExchangeAlgorithms) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($KeyExchangeAlgorithm)
  $key.SetValue('Enabled',0xFFFFFFFF , 'DWord')
  $key.close()
  Write-Host -ForegroundColor DarkGreen "Key-Ex Algorithm $KeyExchangeAlgorithm has been enabled."
}
 
write-host -ForegroundColor Yellow "`n`n********************Protocols********************"
 
$EnabledProtocols = @(
 
    'TLS 1.2'
)
 
$DisabledProtocols = @(
    'Multi-Protocol Unified Hello',
    'NULL',
    'PCT 1.0',
    'SSL 2.0',
    'SSL 3.0',
    'TLS 1.0',
    'TLS 1.1'
)
 
 
Foreach ($EnabledProtocol in $EnabledProtocols) {
     $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols', $true).CreateSubKey($EnabledProtocol)
     $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$EnabledProtocol", $true).CreateSubKey("Client")
     $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$EnabledProtocol", $true).CreateSubKey("Server")
 
     $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$EnabledProtocol\Client", $true)
     $key.SetValue("Enabled",0xFFFFFFFF,'DWord')
     $key.SetValue("DisabledByDefault",0,'DWord')
     Write-Host -ForegroundColor DarkGreen "$EnabledProtocol Client has been enabled."
     $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$EnabledProtocol\Server", $true)
     $key.SetValue("Enabled",0xFFFFFFFF,'DWord')
     $key.SetValue("DisabledByDefault",0,'DWord')
     Write-Host -ForegroundColor DarkGreen "$EnabledProtocol Server has been enabled."
     }
 
Foreach ($DisabledProtocol in $DisabledProtocols) {
     $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols', $true).CreateSubKey($DisabledProtocol)
     $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$DisabledProtocol", $true).CreateSubKey("Client")
     $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$DisabledProtocol", $true).CreateSubKey("Server")
 
     $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$DisabledProtocol\Client", $true)
     $key.SetValue("Enabled",0,'DWord')
     $key.SetValue("DisabledByDefault",0xFFFFFFFF,'DWord')
     Write-Host -ForegroundColor DarkRed "$DisabledProtocol Client has been disabled."
     $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$DisabledProtocol\Server", $true)
     $key.SetValue("Enabled",0,'DWord')
     $key.SetValue("DisabledByDefault",0xFFFFFFFF,'DWord')
     Write-Host -ForegroundColor DarkRed "$DisabledProtocol Server has been disabled."
     }
 
 
write-host -ForegroundColor Yellow "`n`n********************Preferred Ciphier Suite Order********************"
 
# Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
  $os = Get-WmiObject -class Win32_OperatingSystem
if ([System.Version]$os.Version -lt [System.Version]'10.0') {
  Write-Host 'Using cipher suite order for Windows 2k8R2/2012/2012R2.'
  $cipherSuitesOrder = @(
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'
  )
} else {
  Write-Host 'Using cipher suite order for Windows 10/2016 and later.'
    $cipherSuitesOrder = @(
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
  )
  }
 
$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
 
$key = (Get-Item HKLM:\).OpenSubKey('SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002', $true).SetValue("Functions",$cipherSuitesAsString,"String")
Write-Host -ForegroundColor DarkGreen "SSL Cipher Functions Set."
Write-Host $cipherSuitesAsString
 
$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman', $true).SetValue("ServerMinKeyBitLength",4096,"DWord")
$key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman', $true).SetValue("ClientMinKeyBitLength",4096,"DWord")
Write-Host "Diffie-Hellman minimum key size set to 4096 for Client and Server."
 
Install-WebPlatform
Install-UrlRewrite
Configure-IIS-HSTS
Configure-HTTPSReWrite
 
}
 
function Configure-HTTPSReWrite() {
import-module webAdministration
Remove-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -name "." -filter "system.webServer/rewrite/GlobalRules" -AtElement @{name="HTTP to HTTPS Redirect"} -ErrorAction SilentlyContinue
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules" -name "." -value @{name='HTTP to HTTPS Redirect'; patternSyntax='ECMAScript'; stopProcessing='True'}
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules/rule[@name='HTTP to HTTPS Redirect']/match" -name url -value "(.*)"
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules/rule[@name='HTTP to HTTPS Redirect']/conditions" -name "." -value @{input="{HTTPS}"; pattern='^OFF$'}
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "type" -value "Redirect"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "url" -value "https://{HTTP_HOST}/{R:1}"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "redirectType" -value "SeeOther"
write-host -ForegroundColor Green "HTTP to HTTPS ReWrite rule successfully added."
}
 
function Configure-IIS-HSTS() {
import-module webAdministration
$RuleName = "Global HSTS"
$serverVariable = "RESPONSE_Strict_Transport_Security"
    Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/allowedServerVariables" -name "." -AtElement @{name="$serverVariable"} -ErrorAction SilentlyContinue
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name="$serverVariable"}
    Remove-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -name "." -filter "system.webServer/rewrite/outboundRules" -AtElement @{name="$RuleName"} -ErrorAction SilentlyContinue
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.webServer/rewrite/outboundRules" -name "." -value @{name="$RuleName"}
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/rewrite/outboundRules/rule[@name='$RuleName']/match" -name "serverVariable" -value $serverVariable
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/rewrite/outboundRules/rule[@name='$RuleName']/match" -name "pattern" -value ".*"
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/rewrite/outboundRules/rule[@name='$RuleName']/conditions" -name "." -value @{input='{HTTPS}';pattern='on'}
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/rewrite/outboundRules/rule[@name='$RuleName']/action" -name "type" -value "Rewrite"
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/rewrite/outboundRules/rule[@name='$RuleName']/action" -name "value" -value "max-age=31536000; includeSubDomains"
    write-host -ForegroundColor Green "HSTS ReWrite Configured."
}
 
function Install-WebPlatform() {
 write-host Downloading WebPlatform Installer...Please wait
$source = "http://download.microsoft.com/download/C/F/F/CFF3A0B8-99D4-41A2-AE1A-496C08BEB904/WebPlatformInstaller_amd64_en-US.msi"
$destination = "$env:temp\WebPlatformInstaller_amd64_en-US.msi"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($source, $destination)
 write-host Download Complete.
 write-host Starting Installation...
####Silent Install WEB Platform Installer
Start-Process -FilePath $destination -ArgumentList "/q" -Wait
write-host Installation Complete.
}
 
 function Install-UrlRewrite() {
 # Web Platform Installer CLI
$WebPiCMd = 'C:\Program Files\Microsoft\Web Platform Installer\WebpiCmd-x64.exe'
Start-Process -wait -FilePath $WebPiCMd -ArgumentList "/install /Products:UrlRewrite2 /AcceptEula /OptInMU /SuppressPostFinish"
Write-Host "URL ReWrite2 Successfully added."
}
 
if($RunNow) {
Harden-WindowsServer
}