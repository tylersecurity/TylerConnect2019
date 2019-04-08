$pass = 'TylerConnect2019!!!' | ConvertTo-SecureString -AsPlainText -Force
for($i=0;$i -lt 24;$i++) {
New-LocalUser -Name "TylerConnect2019_$i" -Description "TylerConnectDemo" -Password $pass -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "TylerConnect2019_$i" -ErrorAction SilentlyContinue
}