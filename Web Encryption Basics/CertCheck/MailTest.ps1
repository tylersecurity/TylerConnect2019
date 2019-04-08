Function SMTPSettings {
#Enter Email Configuration Info
Write-Host "SMTP Configurations and Options:" 
Write-Host ""

    #Set the SMTP Server Name
    Write-Host "###########################"
    $smtpname = Read-Host 'Enter the SMTP Server Name'
    Write-Host ""
    while ($smtpname -ilike $null) {
        Write-Host "The SMTP Server Name cannot be blank." -BackgroundColor Red
        Write-Host "###########################"
        $smtpname = Read-Host 'Enter the SMTP Server Name'
        Write-Host ""
    }

    #Set the SMTP Port Number
    Write-Host "###########################"
    $smtpport = Read-Host 'Enter the SMTP Port Number'
    Write-Host ""
    while ($smtpport -ilike $null) {
        Write-Host "The SMTP Port Number cannot be blank." -BackgroundColor Red
        Write-Host "###########################"
        $smtpport = Read-Host 'Enter the SMTP Port Number'
        Write-Host ""
    }

    #Set the E-Mail TO Address
    Write-Host "###########################"
    Write-Host "NOTE: The E-Mail TO Address should be set to temsosdba@tylertech.com for Tyler SIS or osdba@munis.com for Munis."
    Write-Host "      Separate multiple e-mail addresses with a comma (,) to CC multiple recipients on the Check Alert E-Mails."
    Write-Host "###########################"
    $mailto = Read-Host 'Enter the E-Mail TO Address'
    Write-Host ""
    while ($mailto -ilike $null) {
        Write-Host "The E-Mail TO Address cannot be blank." -BackgroundColor Red
        Write-Host "###########################"
        $mailto = Read-Host 'Enter the E-Mail TO Address'
        Write-Host ""
    }

    #Set the E-Mail FROM Address
    Write-Host "###########################"
    Write-Host "NOTE: The E-Mail FROM Address needs to match the name of the Primary Contact in Onyx that the ticket will be opened under."
    Write-Host "###########################"
    $mailfrom = Read-Host 'Enter the E-Mail FROM Address'
    Write-Host ""
    while ($mailfrom -ilike $null) {
        Write-Host "The E-Mail FROM Address cannot be blank." -BackgroundColor Red
        Write-Host "###########################"
        $mailfrom = Read-Host 'Enter the E-Mail FROM Address'
        Write-Host ""
    }

    #Set the Use E-Mail Authentication option
    Write-Host "###########################"
    Write-Host "NOTE: Set the E-Mail Authentication option to Yes if the SMTP server requires login credentials."
    Write-Host "###########################"
    $UseAuthentication = Read-Host 'Enable E-Mail Authentication? Yes or No'
    Write-Host ""
    while ($UseAuthentication -ilike $null) {
        Write-Host "The E-Mail Authentication option cannot be blank." -BackgroundColor Red
        Write-Host "###########################"
        $UseAuthentication = Read-Host 'Enable E-Mail Authentication? Yes or No'
        Write-Host ""
    }
    while ($UseAuthentication -ine "Yes" -and $UseAuthentication -ine "No" -and $UseAuthentication -ine "Y" -and $UseAuthentication -ine "N") {
        Write-Host "Invalid entry. Please enter either Yes or No." -BackgroundColor Red
        Write-Host "###########################"
        $UseAuthentication = Read-Host 'Enable E-Mail Authentication? Yes or No'
        Write-Host ""
    }

    if ($UseAuthentication -ieq "Yes" -or $UseAuthentication -ieq "Y") {
        #Set the SMTP Credentials
        $SMTPCreds = Get-Credential -Message "Enter the SMTP username and password."
        $SMTPLoginName = $SMTPCreds.username

        #Create an encrypted password file for the execution account    
        $SMTPCreds.Password | ConvertFrom-SecureString | Set-Content $PSScriptRoot\Bin\encrypted_smtp.txt

        #Set the Use SSL option
        Write-Host "###########################"
        Write-Host "NOTE: Set the SSL option to Yes if the SMTP server requires SSL authentication."
        Write-Host "###########################"
        $UseSSL = Read-Host 'Enable SSL/TLS? Yes or No'
        Write-Host ""
        while ($UseSSL -ilike $null) {
            Write-Host "The SSL/TLS option cannot be blank." -BackgroundColor Red
            Write-Host "###########################"
            $UseSSL = Read-Host 'Enable SSL/TLS? Yes or No'
            Write-Host ""
        }
        while ($UseSSL -ine "Yes" -and $UseSSL -ine "No" -and $UseSSL -ine "Y" -and $UseSSL -ine "N") {
            Write-Host "Invalid entry. Please enter either Yes or No." -BackgroundColor Red
            Write-Host "###########################"
            $UseSSL = Read-Host 'Enable SSL? Yes or No'
            Write-Host ""
        }
    }
    TestEmailConfig
}

function SendEmailTest{
    try {
        
        Write-Host "Sending E-Mail to $mailto through the $smtpname SMTP server..."
        $smtpclient = new-object system.net.mail.smtpclient 
        $mailmessage = new-object system.net.mail.mailmessage 
        $smtpclient.Host = $smtpname
        $smtpclient.Port = $smtpport
        $mailmessage.from = $mailfrom
        $mailmessage.To.add($mailto)
        if ($UseAuthentication -ieq "yes"){
            #Decrypt and set the SMTP credentials
            $smtpencrypted = Get-Content $PSScriptRoot\Bin\encrypted_smtp.txt | ConvertTo-SecureString
            $SMTPCreds = New-Object System.Management.Automation.PsCredential($SMTPLoginName, $smtpencrypted)
            $SMTPPass = $SMTPCreds.GetNetworkCredential().password
            $smtpclient.Credentials = new-object System.Net.NetworkCredential ($SMTPCreds.username, $SMTPPass)
        }
        if ($UseSSL -ieq "yes" -or $UseSSL -ieq "Y"){
            $smtpclient.EnableSSL = $true
        }   
        $mailmessage.Subject = "Check script TEST Alert - Check script Setup Test Message" 
        $mailmessage.Body = "<TABLE><TR><TH>This email alert was created by the IIS Certificate Checkscript during the setup process</TH></TR></TABLE>"
        $mailmessage.isbodyhtml = 1
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
        $smtpclient.Send($mailmessage)

        Write-Host ""
        Write-Host "E-Mail sent successfully" -backgroundcolor darkgreen
        Write-Host ""
        }
    catch {
        write-host "An error occurred while sending the e-mail:" -ForegroundColor Red
        write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
        write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
    }     
}

function TestEmailConfig {
    #Test Email Functionality
    Write-Host "                                "
    Write-Host "Testing Email Functionality....." -BackgroundColor DarkYellow
    Write-Host "                                "
    . SendEmailTest
    Write-Host "###########################"
    $EmailWorks = Read-Host 'Did you receive the test email? Yes or No'
    while ($EmailWorks -ilike $null) {
        Write-Host "The E-Mail Test confirmation cannot be blank." -BackgroundColor Red
        Write-Host "###########################"
        $EmailWorks = Read-Host 'Did you receive the test email? Yes or No'
    }
    while ($EmailWorks -ine "Yes" -and $EmailWorks -ine "No" -and $EmailWorks -ine "Y" -and $EmailWorks -ine "N") {
        Write-Host "Invalid entry. Please enter either Yes or No." -BackgroundColor Red
        Write-Host "###########################"
        $EmailWorks = Read-Host 'Did you receive the test email? Yes or No'
        Write-Host ""
    }
    if ($EmailWorks -ieq "Yes" -or $EmailWorks -ieq "Y") {
        $smtpworks = "Yes"
        write-host ""
        Write-Host "E-Mail Settings Successfully Configured" -BackgroundColor DarkGreen
        Write-Host ""
    }
    if ($EmailWorks -ieq "No" -or $EmailWorks -ieq "N") {

        Write-Host "###########################"
        Write-Host "Please review the SMTP settings you entered:"
        Write-Host "SMTP Server:        $smtpname"
        Write-Host "SMTP Port:          $smtpport"
        Write-Host "Mail To Address:    $mailto"
        Write-Host "Mail From Address:  $mailfrom"
        if ($UseSSL -ieq "Yes" -or $UseSSL -ieq "Y") {
            Write-Host "Username:           $SMTPLoginName"
            Write-Host "Password:           $SMTPPass"
            Write-Host "Use SSL:            $UseSSL"
        }
        Write-Host ""
        Write-Host "###########################"
        $confirmsmtp = Read-Host 'Are the SMTP settings correct? Yes or No'
        Write-Host ""
        while ($confirmsmtp -ilike $null) {
            Write-Host "The SMTP confirmation cannot be blank." -BackgroundColor Red
            Write-Host "###########################"
            $confirmsmtp = Read-Host 'Are the SMTP settings correct? Yes or No'
        }
        while ($confirmsmtp -ine "Yes" -and $confirmsmtp -ine "No" -and $confirmsmtp -ine "Y" -and $confirmsmtp -ine "N") {
            Write-Host "Invalid entry. Please enter either Yes or No." -BackgroundColor Red
            Write-Host "###########################"
            $confirmsmtp = Read-Host 'Are the SMTP settings correct? Yes or No'
            Write-Host ""
        }
        if ($confirmsmtp -ieq "Yes" -or $confirmsmtp -ieq "Y"){
            Write-Host "###########################"
            Write-Host "Please verify that the SMTP server allows SMTP relay from this server: $ENV:ComputerName"
            Write-Host "###########################"
            Write-Host "To test basic SMTP functionality refer to Microsoft Knowledgebase Article ID: 153119"
            Write-Host "http://support.microsoft.com/kb/153119"

            Write-Host "###########################"
            $xforworks = Read-Host 'Did the XFOR Telnet test work? Yes or No'
            Write-Host ""
            while ($xforworks -ilike $null) {
                Write-Host "The XFOR Test confirmation cannot be blank." -BackgroundColor Red
                Write-Host "###########################"
                $xforworks = Read-Host 'Did the XFOR Telnet test work? Yes or No'
            }
            while ($xforworks -ine "Yes" -and $xforworks -ine "No" -and $xforworks -ine "Y" -and $xforworks -ine "N") {
                Write-Host "Invalid entry. Please enter either Yes or No." -BackgroundColor Red
                Write-Host "###########################"
                $xforworks = Read-Host 'Did the XFOR Telnet test work? Yes or No'
                Write-Host ""
            }

            if ($xforworks -ieq "No" -or $xforworks -ieq "N") {
                Write-Host "###########################"
                Write-Host "Please work with your email administrator to enable SMTP relay from this server: $ENV:ComputerName" -BackgroundColor Red
                Write-Host "Once SMTP relaying is functional, please rerun the $PSScriptRoot\AuthEmailSetup.ps1 script from an elevated Powershell window." -BackgroundColor Red
                Write-Host "###########################"
                Write-Host ""
                $smtpworks = "Yes"
            }
            if ($xforworks -ieq "Yes" -or $xforworks -ieq "Y") {

                Write-Host "###########################"
                Write-Host "Please review the SMTP settings you entered:"
                Write-Host "SMTP Server:        $smtpname"
                Write-Host "SMTP Port:          $smtpport"
                Write-Host "Mail To Address:    $mailto"
                Write-Host "Mail From Address:  $mailfrom"
                if ($UseSSL -ieq "Yes" -or $UseSSL -ieq "Y") {
                    Write-Host "Username:           $SMTPLoginName"
                    Write-Host "Password:           $SMTPPass"
                    Write-Host "Use SSL:            $UseSSL"
                }
                Write-Host ""
                Write-Host "###########################"
                $reconfirmsmtp = Read-Host 'Are you certain that the SMTP settings correct? Yes or No'
                Write-Host ""
                while ($reconfirmsmtp -ilike $null) {
                    Write-Host "The SMTP confirmation cannot be blank." -BackgroundColor Red
                    Write-Host "###########################"
                    $reconfirmsmtp = Read-Host 'Are you certain that the SMTP settings correct? Yes or No'
                }
                while ($reconfirmsmtp -ine "Yes" -and $reconfirmsmtp -ine "No" -and $reconfirmsmtp -ine "Y" -and $reconfirmsmtp -ine "N") {
                    Write-Host "Invalid entry. Please enter either Yes or No." -BackgroundColor Red
                    Write-Host "###########################"
                    $reconfirmsmtp = Read-Host 'Are you certain that the SMTP settings correct? Yes or No'
                    Write-Host ""
                }
                if ($reconfirmsmtp -ieq "Yes" -or $reconfirmsmtp -ieq "Y") {
                    #Retest Email Functionality
                    Write-Host "                                "
                    Write-Host "Retesting Email Functionality....." -BackgroundColor DarkYellow
                    Write-Host "                                "
                    . SendEmailTest
                    Write-Host "###########################"
                    $reEmailWorks = Read-Host 'Did you receive the test email? Yes or No'
                    while ($reEmailWorks -ilike $null) {
                            Write-Host "The E-Mail Test confirmation cannot be blank." -BackgroundColor Red
                            Write-Host "###########################"
                            $reEmailWorks = Read-Host 'Did you receive the test email? Yes or No'
                    }
                    while ($reEmailWorks -ine "Yes" -and $reEmailWorks -ine "No" -and $reEmailWorks -ine "Y" -and $reEmailWorks -ine "N") {
                        Write-Host "Invalid entry. Please enter either Yes or No." -BackgroundColor Red
                        Write-Host "###########################"
                        $reEmailWorks = Read-Host 'Did you receive the test email? Yes or No'
                        Write-Host ""
                    }
                    if ($reEmailWorks -ieq "Yes" -or $reEmailWorks -ieq "Y") {
                        $smtpworks = "Yes"
                    }
                    if ($reEmailWorks -ieq "No" -or $reEmailWorks -ieq "N") {
                        Write-Host "###########################"
                        Write-Host "Sorry, but I have no explanation why the test email is not working if the XFOR test was successful and the SMTP settings are correct."
                        Write-Host "Please work with your email administrator to verify that there are no Spam filters or other devices blocking the emails from sending."
                        Write-Host "To test email functionality again later, please rerun the $PSScriptRoot\AuthEmailSetup.ps1 script from an elevated Powershell window." -BackgroundColor Red
                        Write-Host "For now, let's move on."
                        Write-Host "###########################"
                        write-host ""
                    }
                }
                if ($reconfirmsmtp -ieq "No" -or $reconfirmsmtp -ieq "N") {
                    $smtpworks = "No"
                }
            }
        }
        if ($confirmsmtp -ieq "No" -or $confirmsmtp -ieq "N") {
            $smtpworks = "No"
            . SMTPSettings
        }
    }
}

SMTPSettings

if ($SMTPPass) {
       Clear-Variable -Name SMTPPass
} 