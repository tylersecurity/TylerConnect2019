#Requires -RunAsAdministrator
#Requires -Version 5
#Import-Module .\Enable-WinRemoteManagement.ps1
#Enable-WinRemoteManagement -computerName workstation.domain.com
function Enable-WinRemoteManagement($computerName) {
$global:compName = $computerName

	$result = winrm id -r:$global:computerName 2>$null

	Write-Host	
	if ($LastExitCode -eq 0) {
		Write-Host "WinRM already enabled on" $global:compName "..." -ForegroundColor green
	} else {

		Write-Host "Checking if psexec.exe is already downloaded..."
		if(!(Test-Path $PSScriptRoot\PSTools\psexec.exe)) {

		Write-Host "psexec.exe not found in script root...Downloading SysInternals Tools to $PSScriptRoot"

		$url = "https://download.sysinternals.com/files/PSTools.zip"
		$output = "$PSScriptRoot\PSTools.zip"
		$start_time = Get-Date

		(New-Object System.Net.WebClient).DownloadFile($url, $output)
		
		Write-Output "Download completed in $((Get-Date).Subtract($start_time).Seconds) second(s)"
		Write-Host "Extracting PSTools.zip to $PSScriptRoot"
		Expand-Archive $PSScriptRoot\PSTools.zip -Force
		} else {
			Write-Host "PSExec already exists in $PSScriptRoot, no need to download it again"
		}

		Write-Host "Enabling WinRM on" $global:compName "..." -ForegroundColor red
		& $PSScriptRoot\PSTools\psexec.exe \\$global:compName -s C:\Windows\system32\winrm.cmd qc -quiet
		if ($LastExitCode -ne 0) {
			Write-Host "Something didn't go quite right...trying to start WinRM manually"
			& $PSScriptRoot\PSTools\psexec.exe \\$global:compName net start WinRM
			$result = winrm id -r:$global:compName 2>$null
		}
			if ($LastExitCode -eq 0) {Write-Host 'WinRM successfully enabled!' -ForegroundColor green}
			else {return "winrm quickconfig failed to setup WinRM."}
		} 
	}
