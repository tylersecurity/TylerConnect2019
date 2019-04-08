########################################
#Certificate Expiration threshold window
$CertCheckThreshold = 60
########################################
#################################################
#Set number of days to delay repeat email notices
$DaysToDelay = 7
#################################################
###################################
#SMTP Settings
$SMTPServer = "smtp.example.com"
$SMTPPort = 25
$To = "recipient@example.com"
$From = "sender@example.com"
$UseAuthentication = "No"
$SMTPUsername = "username"
$UseSSL = "No"
$TestMode = "No"
###################################

#Other Needed variables
$wmi = (Get-WmiObject -ComputerName localhost Win32_OperatingSystem)
$compname = $wmi.CSName
$outfilepath = "$PSScriptRoot\results\"
$outfile = "$PSScriptRoot\results\" + (Get-Date -format yyyy-M-dTHHmmss) + ".html"
$logtime = (Get-Date -format "yyyy-MM-dd HH:mm:ss.fff")
$OutputFileDaysToSave = 14
$errs = $null

#CertCheck function
function CertCheck {
    $script:sqlerr = 0
	trap {
		Write-Host "An error occured accessing IIS"
		Write-Host  -BackgroundColor red ("Message:  " + $_.Exception.Message)
		$script:sqlerr = 1
		}

    Write-Host "Importing WebAdministration module"
    Import-Module WebAdministration 
    $sites = get-website

    switch ($script:sqlerr){
			1{	if ($_.Exception.Message -ne $null) {
                    Write-Host -BackgroundColor Red "Error occured accessing master IIS"
                    OutfileOpenTable 2 "IIS Certificate Check"
                    OutfileHeaderRow @("Site","Output")
				    OutfileDataRow @($($_.Exception.Message), "Failed") "Red"				
				    $err = @{Check = "IIS Certs"; Error = "Failed to connect to IIS Server"; Sum = "IIS connection failed"}
				    $script:errs += @($err)
                }
			  }
			0 {
                OutfileOpenTable 2 "IIS Results"
                OutfileHeaderRow @("Site","Output")
                foreach ($site in $sites) {
                    $sitename = $site.name
                    $siteid = $site.id
                    $sitestate = $site.state
                    $sitepath = $site.physicalPath
                    $sitebindings = ($site.bindings | select -expa collection) -join '; '
                    $sitelog = $site.logfile | select -expa directory
                    $siteattributes = ($site.attributes | % { $_.name + "=" + $_.value }) -join '; '

                    write-host "Site Name:     $sitename"
                    write-host "Site ID:       $siteid"
                    write-host "State:         $sitestate"
                    write-host "Physical Path: $sitepath"
                    write-host "Bindings:      $sitebindings"
                    write-host "Log File Path: $sitelog"
                    write-host "Attributes:    $siteattributes"
                    write-host ""

                    OutfileDataRow @("Site Name:", $sitename)
                    OutfileDataRow @("Site ID:", $siteid)
                    if ($sitestate -inotlike "*Started*") {
                    write-host "$sitename is not started." -ForegroundColor Red
                    OutfileDataRow @("State:", $sitestate) "Red"
                    OutfileDataRow @(" ", " ")
                    
                                        				
				    $err = @{Check = "IIS Check"; Error = "$sitename is not started"; Sum = "Site not started"}
				    $script:errs += @($err)
                    }
                    else {OutfileDataRow @("State:", $sitestate)}
                    OutfileDataRow @("Physical Path:", $sitepath)
                    OutfileDataRow @("Bindings:", $sitebindings)
                    OutfileDataRow @("Log File Path:", $sitelog)
                    OutfileDataRow @("Attributes:", $siteattributes)
                    OutfileDataRow @(" "," ")
                }

                #determine if there is a site binding to port 443
                $binding = Get-ChildItem IIS:\SslBindings
                write-host "Checking for SSL Certificates..."
                write-host ""

                if ($binding.port -eq 443) {
                    

                    $threshold = $CertCheckThreshold   #Number of days to look for expiring certificates 
                    $deadline = (Get-Date).AddDays($threshold)   #Set deadline date 
                    $certs = Dir Cert:\LocalMachine\My 
                    Write-Host "Active Certificates Found:"


                foreach ($cert in $certs) { 
                if ($cert.Issuer -inotlike "*CN=UTN-USERFirst*") {
                    $Issuer= $cert.Issuer
                    if ($issuer -inotlike "*,*") {
                        $IssuedBy = $Issuer.Substring(3)
                    }
                    if ($Issuer -ilike "*,*") {
                        $IssuedBy = [regex]::match($Issuer,'\=([^\,]+)\,').Groups[1].Value
                    }

                    $Subject = $cert.Subject
                    if ($Subject -inotlike "*,*") {
                        $IssuedTo = $Subject.Substring(3)
                    }
                    if ($Subject -ilike "*,*") {
                        $IssuedTo = [regex]::match($Subject,'\=([^\,]+)\,').Groups[1].Value
                    }
                    $ExpireDate = $cert.NotAfter
                    $DaysToExpire = (($cert.notafter  - (Get-Date)).Days)
                    $Thumb = $cert.thumbprint

                    If ($ExpireDate -le $deadline) { 
                        write-host "Certificate About To Expire:" -ForegroundColor Red
                        write-host "Thumbprint:         $Thumb" -ForegroundColor Red
                        write-host "Issued By:          $IssuedBy" -ForegroundColor Red
                        write-host "Issued To:          $IssuedTo" -ForegroundColor Red
                        write-host "Expiration Date:    $ExpireDate" -ForegroundColor Red
                        write-host "Expires In (Days):  $DaysToExpire" -ForegroundColor Red
                        write-host ""

                        OutfileDataRow @("Thumbprint:", $Thumb) "Red"
                        OutfileDataRow @("Issued By:", $IssuedBy) "Red"
                        OutfileDataRow @("Issued To:", $IssuedTo) "Red"
                        OutfileDataRow @("Expiration Date:", $ExpireDate) "Red"
                        OutfileDataRow @("Expires In (Days):", $DaysToExpire) "Red"
                        OutfileDataRow @(" ", " ")
                        
                        #Test to determine if email notice should be sent
                        $Pattern = "<TR bgcolor=Red><TD>Thumbprint:</TD>"
                        $ResultsErrorCount = DelayEmailNotice -pattern $Pattern
                        #send email notice
                        if ($ResultsErrorCount -le 1) {
                            $err = @{Check = "IIS Certs"; Error = "Certificate About To Expire"; Sum = "SSL cert expiring"}
				            $script:errs += @($err)
                        }
                        #Send email notice if error has occurred for last $DaysToDelay days
                        elseif ($ResultsErrorCount / $DaysToDelay -eq 1) {
                            $err = @{Check = "IIS Certs"; Error = "Certificate About To Expire"; Sum = "SSL cert expiring"}
				            $script:errs += @($err)
                        }
                        Clear-Variable -Name ResultsErrorCount
                    }
                    else {
                        write-host "Thumbprint:         $Thumb"
                        write-host "Issued By:          $IssuedBy"
                        write-host "Issued To:          $IssuedTo"
                        write-host "Expiration Date:    $ExpireDate"
                        write-host "Expires In (Days):  $DaysToExpire"
                        write-host ""

                        OutfileDataRow @("Thumbprint:", $Thumb)
                        OutfileDataRow @("Issued By:", $IssuedBy)
                        OutfileDataRow @("Issued To:", $IssuedTo)
                        OutfileDataRow @("Expiration Date:", $ExpireDate) 
                        OutfileDataRow @("Expires In (Days):", $DaysToExpire)
                        OutfileDataRow @(" ", " ")
                        }
                    }
                  }
                }

    elseif ($binding.Port -ne 443) {
        write-host "No SSL certificates found."
        write-host ""

        OutfileDataRow @("No SSL certificates found", "$sitename is not bound to port 443")
        }
   }
  }
OutfileCloseTable
}

#Helper Functions
function OutputDivider{
	Write-Host ""
	Write-Host "***************************************************"
	Write-Host ""
}

function DeleteOutputFiles{
	OutputDivider
	Write-Host "Cleaning up old result files."
	$directory = $outfilepath
	$contents = Get-ChildItem -Path $directory -Filter "*.html"
	$todaysdate = get-date

    
	foreach ($file in $contents){
		$span = New-TimeSpan -Start $file.CreationTime -End $todaysdate
		if ($span.days -gt $OutputFileDaysToSave){
			Write-Host ($file.name + " is " + $span.days + " days old.  Threshhold is " + $OutputFileDaysToSave + ".  Deleting file") 
			$file | Remove-Item    
		}
		if ($span.days -le $OutputFileDaysToSave){
			Write-Host ($file.name + " is " + $span.days + " days old.  Threshhold is " + $OutputFileDaysToSave + ".  Saving file")
		}
	}


}

#Determines if the given $pattern error string occurs in the results files for the last number of days ($DaysToDelay). Used to delay email notices by X days
function DelayEmailNotice ($pattern) {
    $Path = $outfilepath
    $PathArray = @()

    # This code snippet gets the files in $Path that end in ".html" newer than $DaysToDelay days old that contain the $pattern string.
    Get-ChildItem $Path -Filter "*.html" | 
       Where-Object {$_.Attributes -ne "Directory"} | Sort-Object $_.CreationTime -Descending |
          ForEach-Object { 
             If (Get-Content $_.FullName | Select-String -Pattern $Pattern) {
                $PathArray += $_.CreationTime
             }
          }
    #Determines if the number of files containing $pattern string 
    $NumberOfErrors = $PathArray.Count
    return $NumberOfErrors
} 

#HTML output to file functions
function OutfileStartFile {
    Add-Content -Path $outfile -Value "<HTML>"
    #OutfileOpenTable -cols 1 -id "version" -title "IIS Certificate Check"
    #OutfileCloseTable
}
function OutfileOpenTable($cols, $title, $id){
	Add-Content -path $outfile -value  "<TABLE width=100% border=1>"
    if ($id) {
	    Add-Content -path $outfile -value  "<TR><TH colspan=$cols id=$id>$title</TH></TR>"
        }
    else {Add-Content -path $outfile -value  "<TR><TH colspan=$cols>$title</TH></TR>"}
	}
function OutfileHeaderRow($items){
    $row = "<TR>"
	foreach ($item in $items){
		$row += "<TH>$item</TH>"
	}
	$row += "</TR>"
	Add-Content -Path $outfile -Value $row
}
function OutfileDataRow($items, $color){
$row = "<TR bgcolor=$color>"
	foreach ($item in $items){
		$row += "<TD>$item</TD>"
	}
	$row += "</TR>"
	Add-Content -Path $outfile -Value $row

}
function OutfileCloseTable{
	Add-Content -Path $outfile -Value "</TABLE>"
	Add-Content -Path $outfile -Value "</BR>"
}
function OutfileEndFile {
    Add-Content -Path $outfile -Value "</HTML>"
}

#Send Email
function SendEmail{
                $smtpclient = new-object system.net.mail.smtpclient 
                $mailmessage = new-object system.net.mail.mailmessage 
                $smtpclient.Host = $SMTPServer
                $smtpclient.Port = $SMTPPort
                $mailmessage.from = $From
                $mailmessage.To.add($To)
    if ($UseAuthentication -ieq "yes"){
        #Decrypt and set the SMTP credentials
        $smtpencrypted = Get-Content $PSScriptRoot\Bin\encrypted_smtp.txt | ConvertTo-SecureString
        $SMTPCreds = New-Object System.Management.Automation.PsCredential($SMTPUsername, $smtpencrypted)
        $SMTPPass = $SMTPCreds.GetNetworkCredential().password
        $smtpclient.Credentials = new-object System.Net.NetworkCredential ($SMTPCreds.username, $SMTPPass)
        }
    if ($UseSSL -ieq "yes"){
       $smtpclient.EnableSSL = $true
       }   

    #Build the Email Body
        #Load outfile
        $latest = Get-ChildItem -Path $outfilepath | Sort-Object LastAccessTime -Descending | Select-Object -First 1
        $htmloutfile = $outfilepath + $latest.name
        $html = Get-Content $htmloutfile
        $SubjectPattern =  '(?i)<div id="Subject"[^>]*>(.*?)</div>'

        if ($TestMode -ieq "yes"){
            $mailmessage.Subject = "TEST Alert - CertCheck script is in TEST Mode" 
            $mailmessage.Body = "<TABLE><TR><TH>This email alert was created by the Cert Check script in test mode</TH></TR>"
            $mailmessage.Body += "<TR><TH>Test mode sends an email alert every time the script is run regardless of results<TH></TR>"
            $mailmessage.Body += "<TR><TH>To discontinue these alerts please set test mode to NO in the CertCheck.ps1 file</TH></TR></TABLE>"
            } 
        else {
            $mailmessage.Subject = "IIS Cert Check Warning - $compname"
            }
        $mailmessage.Body += $html
        $mailmessage.isbodyhtml = 1
        $smtpclient.Send($mailmessage)                  
        
}

#Main
clear
Outputdivider

#Verify the outfile directory exists. If not, create it.
if (!(Test-Path -Path $outfilepath)) {
New-Item -ItemType directory -Path $outfilepath | out-null
Write-Host "The Result File Directory is $outfilepath"
Write-Host ""
}

OutfileStartFile
Write-Host "Output file is: $outfile"

#Check Certs
CertCheck

#Close out file
OutfileEndFile

#Check if errors occurred and record to file
if ($errs -ne $null) {
    Write-Host "Errors encountered were:" -BackgroundColor Red
    $errs 
    #Write the total number of errors to the output file
    Add-Content -path $outfile -value  "<input type=`"hidden`" value=`"$($errs.count)`" id=`"Errors`"/>"
    #Create the email subject line and store it in the outfile
    if ($config.EmailInfo.DetailedSubject -ieq "yes") {
        $Subject = ("CertCheck Alert - " + $compname)
        foreach ($err in $errs){        
            $Subject += (" - " + $err.Sum)
        }
    } 
    else {
        $Subject = ("CertCheck Alert - " + $config.EmailInfo.SiteName + " - " + $compname)
    }
    #Create the error table and write it to the top of the outfile 
    Add-Content -path $outfile -value "<div id=`"Subject`" style=`"display:none;`">"
    Add-Content -path $outfile -value $Subject
    Add-Content -path $outfile -value "</div>"
    $Body = "<TABLE width=100% border=1><TR><TH colspan=2 bgcolor=#FF0303>The following errors occurred on " + $compname + "</TH></TR>"
    $Body += "<TR><TH>Check</TH><TH>Error</TH></TR>"
        foreach ($err in $errs){
            $Body += "<TR><TD>" + $err.Check + "</TH><TH>" + $err.Error + "</TH></TR>"
        }
    $Body += "</TABLE></BR>"
    $addline = '<HTML>' + "`r`n$Body"
    if ($Body) {
        (Get-Content $outfile) -replace '<HTML>', $addline | Out-File -FilePath $outfile
    }
}

#check if mail should be sent
if (($errs) -or ($TestMode -ieq "yes")) {
    SendEmail
}
else {
    Write-Host "No errors were encountered"
} 

Outputdivider
DeleteOutputFiles

#Mark the completion of the script
Outputdivider
write-host "Script Execution Complete on $compname"
write-host ""
Write-Host "******************************************************************************************************"
Write-Host "******************************************************************************************************"
write-host ""