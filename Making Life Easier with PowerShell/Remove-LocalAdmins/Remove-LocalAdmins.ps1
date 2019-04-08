 <#
 .SYNOPSIS
 Remove-LocalAdmins from workstations
 .DESCRIPTION
This script will load a list of computers and a list of users and try to remove each specified user from the Administrators group if they exist.
  
 .EXAMPLE
 Remove-LocalAdmins -LogPath C:\Temp\RemoveAdmins.log -ComputerNames C:\Temp\computers.txt -RemoveUsers C:\temp\removeusers.txt
 .PARAMETER LogPath
 File path to write the transaction log to.
 .PARAMETER ComputerNames
 Line separated list of computer names to connect to
 .PARAMETER RemoveUsers
 Line separated list of user names to remove from the Administrators group for the specified ComputerNames
 #>
Param
(
 [Parameter(Mandatory=$false)]
 [string]$LogPath = ".\Remove-LocalAdmins.log",
 [Parameter(Mandatory=$true)]
 [string]$ComputerNames,
 [Parameter(Mandatory=$true)]
 [string]$RemoveUsers
)
 
$Date = Get-Date -UFormat %b-%m-%Y 
$Hour = (Get-Date).Hour 
$Minuntes = (Get-Date).Minute 
 
#Creates a log file for this process 
Start-Transcript -Path $LogPath  -Force  
 
#List of computers to be check 
$ComputerNames = Get-Content $ComputerNames 
 
#Ping the computers on the list 
foreach ($ComputerName in $ComputerNames) { 
 
#If theres no ping answer pass to the next one 
if ( -not(Test-Connection $ComputerName -Quiet -Count 1 -ErrorAction Continue )) { 
Write-Output "Computer $ComputerName not reachable (PING) - Skipping this computer..." } 
 
#If computer does answer the ping 
Else { Write-Output "Computer $computerName is online" 
 
#Search into the local Administrators group 
$LocalGroupName = "Administrators" 
$Group = [ADSI]("WinNT://$computerName/$localGroupName,group") 
$Group.Members() | 
foreach { 
$AdsPath = $_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null) 
$A = $AdsPath.split('/',[StringSplitOptions]::RemoveEmptyEntries) 
$Names = $a[-1]  
$Domain = $a[-2] 
 
foreach ($name in $names) { 
Write-Output "Verifying the local admin users on computer $computerName"  
$Admins = Get-Content $RemoveUsers
foreach ($Admin in $Admins) { 
if ($name -eq $Admin) { 
 
#If we find a match, notify and then remove from the local administrators group 
Write-Output "User $Admin found on computer $computerName ... " 
$Group.Remove("WinNT://$computerName/$domain/$name") 
Write-Output "User removed from local administrator group." }}}}} 
 
}Stop-Transcript