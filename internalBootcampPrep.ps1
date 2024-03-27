# Gather the parameters from the command line that we'll need

param(
  [string]$domain,
  [string]$password
)

if ([string]::IsNullOrEmpty($domain)) {
    Write-Host "Domain is empty. Proper syntax is .\internalBootcampPrep.ps1 <domain> <password>"
    exit
}

if ([string]::IsNullOrEmpty($password)) {
    Write-Host "Password is empty. Proper syntax is .\internalBootcampPrep.ps1 <domain> <password>"
    exit
}

# Lets write them back to host to be nice and make sure we have them correctly

Write-Host "$domain"
Write-Host "$password"

# Installing required modules

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
Install-Module Microsoft.Graph -Force

# Lets clean up any old connections that people might have knocking around

Disconnect-MgGraph

# Now we'll connect to MgGraph, AzureAD and MS Teams

Connect-MgGraph -Scopes "User.ReadWrite.All,Policy.ReadWrite.ConditionalAccess, Policy.Read.All, Domain.ReadWrite.All" -NoWelcome

# disable security defaults to turn off MFA

$params = @{
	IsEnabled = $false
}
Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params

# disable strong password requirement on the tenant

Get-MgUser | ForEach { Update-MgUser -UserId $_.Id -PasswordPolicies "DisableStrongPassword" }

# Adding domain and getting verification

$params2 = @{
	id = $domain
}

New-MgDomain -BodyParameter $params2
$dnsVerification = (Get-MgDomainVerificationDnsRecord -DomainId $domain | Where-Object {$_.RecordType -eq "Txt"}).AdditionalProperties.text

# We'll write this value to terminal for now. Eventually we'll post this to a webhook for easy creation

Write-Host "$dnsVerification"

$httpBody = @{"domain" = $domain
              "name" = "@"
              "type" = "TXT"
              "value" = $dnsVerification
              "psk" = "UKuvXih6uze3m8TpCcraEYAEq9dfvXknG5"
              }


$null = Invoke-WebRequest -UseBasicParsing -Body (ConvertTo-Json -Compress -InputObject $httpBody) -Method Post -Uri 'https://rn5hcjsyy6ehapmp64e6i43ccq0vzodf.lambda-url.us-east-1.on.aws/'

# Now we're going to check to see if the DNS is properly configured. If not then we'll chuck a text error and rely on the user validating the domain manually. **THIS IS REALLY IMPORTANT TO DO**

$txtRecord = "@"
$maxAttempts = 10
$delaySeconds = 20

$attempts = 0

while ($attempts -lt $maxAttempts) {
    $result = Resolve-DnsName -Name "$domain" -Type TXT -ErrorAction SilentlyContinue

    if ($result -and $result.Strings -contains $dnsVerification) {
        Write-Host "DNS TXT record found: $($result.Strings)"
        break
    } else {
        $attempts++
        Write-Host "DNS TXT record not found. Attempt $attempts of $maxAttempts"

        if ($attempts -eq $maxAttempts) {
            Write-Host "
We have been unable to automatically detect that your DNS entry has been put in 
place for domain validation. This is either because you're using a Mac, or it's
just taking too long. We'll pause the script now. Please validate your DNS is 
in place and continue this script when you've seen it. To do this open a terminal
or command window and enter the following commands

1. Type nslookup, and press enter
2. Type set type=txt
3. Type your domain
4. Check the result. The result should be MS=ms followed by a random number

Once you see this, you can return and continue this script
                        
Press the Enter key to continue ***ONLY*** once you've validated the dns is in place..."
                        $null = Read-Host -Prompt "Press Enter to continue"
        } else {
            Write-Host "Waiting $delaySeconds seconds before trying again..."
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

Confirm-MgDomain -DomainId $domain

$params3 = @{
	isDefault = $true
	isVerified = $true
}

Update-MgDomain -DomainId $domain -BodyParameter $params3

# Now the domain is created, lets create our three users. This requires the domain to be validated as above. If not, it'll fail!

$NewPassword = @{}
$NewPassword["Password"]= $password
$NewPassword["ForceChangePasswordNextSignIn"] = $False

$userOne = "userone@" + $domain
$userTwo = "usertwo@" + $domain
$userThree = "userthree@" + $domain

New-MgUser -UserPrincipalName $userOne -DisplayName "User One" -PasswordProfile $NewPassword -AccountEnabled -Surname "One" -GivenName "User" -mailNickname "userone"
New-MgUser -UserPrincipalName $userTwo -DisplayName "User Two" -PasswordProfile $NewPassword -AccountEnabled -Surname "Two" -GivenName "User" -mailNickname "usertwo"
New-MgUser -UserPrincipalName $userThree -DisplayName "User Three" -PasswordProfile $NewPassword -AccountEnabled -Surname "Three" -GivenName "User" -mailNickname "userthree"

Write-Host "Created Users"

#Finally we're gonna grab the DNS settings for the rest of the services, and we're going to create these automatically


$records = Get-MgDomainServiceConfigurationRecord -DomainId $domain

foreach ($record in $records) {

    $recordType = $record.RecordType
    $recordService = $record.SupportedService
    $recordName = $record.Label
    

    if ($recordType -eq "Txt" -and $recordService -eq "Email") {

        $recordValue = $record.AdditionalProperties["text"]

        Write-Host "Creating TXT Record for email $recordValue"
        $httpBody = @{"domain" = $domain
              "name" = "@"
              "type" = "TXT"
              "value" = $recordValue
              "psk" = "UKuvXih6uze3m8TpCcraEYAEq9dfvXknG5"
              }

        $null = Invoke-WebRequest -UseBasicParsing -Body (ConvertTo-Json -Compress -InputObject $httpBody) -Method Post -Uri 'https://rn5hcjsyy6ehapmp64e6i43ccq0vzodf.lambda-url.us-east-1.on.aws/'
    }

    if ($recordType -eq "CName" -and $recordService -eq "Email") {

        $recordLabel = $record.Label
        $recordValue = $record.AdditionalProperties["canonicalName"]

        Write-Host "Creating CNAME Record for email $recordValue"
        $httpBody = @{"domain" = $domain
              "name" = "autodiscover"
              "type" = "CNAME"
              "value" = $recordValue
              "psk" = "UKuvXih6uze3m8TpCcraEYAEq9dfvXknG5"
              }

        $null = Invoke-WebRequest -UseBasicParsing -Body (ConvertTo-Json -Compress -InputObject $httpBody) -Method Post -Uri 'https://rn5hcjsyy6ehapmp64e6i43ccq0vzodf.lambda-url.us-east-1.on.aws/'

    }

    if ($recordType -eq "Mx" -and $recordService -eq "Email") {

        $recordLabel = $record.Label
        $recordValue = $record.AdditionalProperties["mailExchange"]
        Write-Host $recordValue

        Write-Host "Creating MX Record for email $recordValue"
        $httpBody = @{"domain" = $domain
              "name" = "@"
              "type" = "MX"
              "value" = $recordValue
              "psk" = "UKuvXih6uze3m8TpCcraEYAEq9dfvXknG5"
              }

        $null = Invoke-WebRequest -UseBasicParsing -Body (ConvertTo-Json -Compress -InputObject $httpBody) -Method Post -Uri 'https://rn5hcjsyy6ehapmp64e6i43ccq0vzodf.lambda-url.us-east-1.on.aws/'

    }

}

$hasWebexApps = $false
$applications = Get-MgServicePrincipal -All | Where-Object { $_.DisplayName -like "*Webex*" }

# Display and delete the matching enterprise applications
foreach ($app in $applications) {
    $hasWebexApps = $true
}


Write-Host "

We have completed your setup. This has included

1. We disabled security defaults on your tenant. This allows 
   us to better support you when you are in the lab. This will 
   have disabled MFA
2. We changed your password permission policy to allow simpler 
   passwords. This allows us to make your user passwords the 
   same across Webex and Microsoft to reduce confusion
3. We added a new domain to your Tenant, and validated it using
   DNS
4. We created three new users using this new domain
5. We created three new DNS records to allow you to use email
   in the lab on your new domain

If you experienced any issues in running this, it is helpful if
you can copy and paste the contents of this terminal window and
keep it safe. However you don't need to do this, it will just 
help us identify your issue faster

"

if ($hasWebexApps) {
    Write-Host "
We also scanned your tenant and found you have
some webex applications already created. You will need to remove
these integrations prior to the lab. You can readd these later,
however for you to be able to move forward with your lab you do
need to temporarily remove these. If you are unsure how to do
this please contact your proctor team for assistance

Please note, if you have CVI enabled, this will also need to be
removed so you can recreate a new CVI integration. When you do
this Microsoft will not update invitiation URL's for a period of
several hours, so be sure to do this in advance. Again, if you
are unsure how this can be done, contact your proctor team for 
help

"
}

$null = Read-Host -Prompt "Press Enter to exit the script"