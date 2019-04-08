Steps to configure IIS Cert Check Script Notifications:
*******************************************************
NOTE: The below steps must be run as on account that has local administrative rights to the IIS server
*******************************************************
1. Save the "CertCheck" directory to "C:\Scripts"
2. Launch PowerShell as Administrator
3. Change the PowerShell directory to "C:\Scripts\CertCheck\"
	cd c:\Scripts\CertCheck\
4. Run the MailTest.ps1 script
	./MailTest.ps1
5. Follow the prompts in the setup script
6. Edit the CertCheck.ps1 file in a text editor
7. Change the following values at the top of the script as desired:
	$CertCheckThreshold: set the number of days before a certificate expires that you want to be notified
		(Default is 60 days)
	$DaysToDelay: Set the number of days that you  want the script to wait before sending you a 2nd notice
		(Default is 7 days)
8. Change the following values to match your SMTP settings as needed
	$SMTPServer
	$SMTPPort
	$To
	$From
9. If your SMTP server requires authentication, set the following values at the top of the script:
	(Note: The encrypted password file gets created in the Bin folder when the MailTest.ps1 file is run)
	$UseAuthentication
	$SMTPUsername
	$UseSSL
10. If desired, set the $TestMode to "Yes" to have the script send the report in an email every time the script runs
11. To schedule the script to run daily
		- Open Task Scheduler
		- Choose "Import Task" under the "Action" menu
		- Browse to C:\Scripts\CertCheck\ and select IIS Certificate Check Scheduled Task.xml
		- Click "Change User or Group" and set the user to the account used while setting up the above steps
		- If Desired, change the schedule that the task will run as under the "Triggers" tab.
- Click OK