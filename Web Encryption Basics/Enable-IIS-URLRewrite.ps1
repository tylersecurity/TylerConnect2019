#Requires -RunAsAdministrator
param (
    [parameter(Mandatory=$false)][Switch]$RunNow
    )

<#
 .SYNOPSIS
 Configure IIS on the local server to re-write all HTTP requests to HTTPS without any interaction from the client.
 .DESCRIPTION
 NOTE: This script must be run from a PowerShell session with elevated permissions.
 This script has been tested on Server 2008R2 SP1, Server 2012 R2, and Server 2016.
	-Installs IIS Web Platform Installer
	-Installs IIS URL Rewrite add-on from https://www.iis.net/downloads/microsoft/url-rewrite
	-Configures and enables HTTP to HTTPS rewrite rules
********************
CAUTION: Always test any and all scripts in a test environment first. All sites hosted by IIS *MUST* have a valid SSL Certificate to remain functional after running this script.
********************
  .EXAMPLE
 .\Enable-IIS-URLRewrite.ps1 -RunNow
 .EXAMPLE
 Import-Module .\Enable-IIS-URLRewrite.ps1
 Enable-IIS-URLRewrite
 .PARAMETER RunNow
 Execute the Script Now
 #>

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

function Config-HTTPSReWrite() {
import-module webAdministration
  
# Create URL Rewrite Rules
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules" -name "." -value @{name='HTTP to HTTPS Redirect'; patternSyntax='ECMAScript'; stopProcessing='True'}
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules/rule[@name='HTTP to HTTPS Redirect']/match" -name url -value "(.*)"
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules/rule[@name='HTTP to HTTPS Redirect']/conditions" -name "." -value @{input="{HTTPS}"; pattern='^OFF$'}
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "type" -value "Redirect"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "url" -value "https://{HTTP_HOST}/{R:1}"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "redirectType" -value "SeeOther"
write-host -ForegroundColor Green "HTTP to HTTPS ReWrite rule successfully added."
}

function Enable-IIS-URLRewrite() {
	if($RunNow) {
		Install-WebPlatform
		Install-URLRewrite
		Config-HTTPSReWrite
		}
}