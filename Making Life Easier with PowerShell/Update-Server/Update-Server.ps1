#Run Windows Update
try {
Import-Module PSWindowsUpdate
} catch {
Write-Host "Windows Update module not installed. Installing."
Install-Module PSWindowsUpdate -Force -Confirm:$false
} finally {
#Install Security and Critical Updates only, optionally remove the category altogether to install all available updates, commented out for demo reasons
#Get-WUInstall -MicrosoftUpdate -AcceptAll
#Get-WUInstall -MicrosoftUpdate -Category 'Security Updates','Critical Updates' -AcceptAll
Send-MailMessage -From "joel.stuedle@tylertech.com" -To "joel.stuedle@tylertech.com" -Subject "[Update-Server] - Connect 2016 Server Reboot Notification" -Body ("Server reboot initiated on " + (Get-Date).DateTime + " after applying Windows Updates.") -SmtpServer "relay.tylertech.com" -Port 25 -BodyAsHtml
Restart-Computer
}
