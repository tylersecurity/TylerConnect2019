 <#
 .SYNOPSIS
 Get-FolderPermissions lists Security/NTFS Permissions for a folder.
 .AUTHOR
 Joel Stuedle
 .COMPANY
 Tyler Technologies
 .DESCRIPTION
This script creates a CSV report with the Security/NTFS permissions applied to a folder and its child items. NOTE: This function does *NOT* report on Share permissions.
 .EXAMPLE
 Get-FolderPermissions -Folder C:\Temp -PermissionsReport C:\Temp\MyFolderPermissions.csv"
 .PARAMETER ReportPath
 File path to write the CSV report to.
 .PARAMETER Folder
 The folder you'd like to retrieve the permissions for.
 #>
Param
(
 [Parameter(Mandatory=$false)]
 [string]$PermissionReport = ".\PermissionsReport.csv",
 [Parameter(Mandatory=$true)]
 [string]$Folder
)

#Get Permissions at the Root or Top Level Folder
Get-Item -Path $Folder | get-acl | %{$_| Add-Member -NotePropertyName Folder -NotePropertyValue (Convert-Path $_.path) -PassThru }|select -ExpandProperty access -property Folder, owner|Export-CSV $PermissionReport -NoTypeInformation

#Recursively get permissions for all child folders
Get-ChildItem -recurse -force $Folder -Directory | get-acl | %{$_| Add-Member -NotePropertyName Folder -NotePropertyValue (Convert-Path $_.path) -PassThru }|select -ExpandProperty access -property Folder, owner|export-csv $PermissionReport -Append -NoTypeInformation

