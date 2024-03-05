<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
	[Parameter(Mandatory=$true)]
	$User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

	$AadModule = Get-Module -Name "AzureAD" -ListAvailable

	if ($AadModule -eq $null) {

		Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
		$AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

	}

	if ($AadModule -eq $null) {
		write-host
		write-host "AzureAD Powershell module not installed..." -f Red
		write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
		write-host "Script can't continue..." -f Red
		write-host
		exit
	}

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

	if($AadModule.count -gt 1){

		$Latest_Version = ($AadModule | select version | Sort-Object)[-1]

		$aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

			# Checking if there are multiple versions of the same module found

			if($AadModule.count -gt 1){

			$aadModule = $AadModule | select -Unique

			}

		$adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
		$adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

	}

	else {

		$adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
		$adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

	}

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

# Using this authentication method requires a clientID.  Register a new app in the Entra ID admin center to obtain a clientID.  More information
# on app registration and clientID is available here: https://learn.microsoft.com/entra/identity-platform/quickstart-register-app 

$clientId = "<replace with your clientID>"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"

	try {

	$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

	# https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
	# Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

	$platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

	$userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

	$authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

		# If the accesstoken is valid then create the authentication header

		if($authResult.AccessToken){

		# Creating header for Authorization token

		$authHeader = @{
			'Content-Type'='application/json'
			'Authorization'="Bearer " + $authResult.AccessToken
			'ExpiresOn'=$authResult.ExpiresOn
			}

		return $authHeader

		}

		else {

		Write-Host
		Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
		Write-Host
		break

		}

	}

	catch {

	write-host $_.Exception.Message -f Red
	write-host $_.Exception.ItemName -f Red
	write-host
	break

	}

}

####################################################

Function Get-IntuneApplication(){

<#
.SYNOPSIS
This function is used to get applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any applications added
.EXAMPLE
Get-IntuneApplication
Returns any applications configured in Intune
.NOTES
NAME: Get-IntuneApplication
#>

[cmdletbinding()]

param
(
	$Name
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps"

	try {

		if($Name){

		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") -and (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

		}

		else {

		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

		}

	}

	catch {

	$ex = $_.Exception
	Write-Host "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" -f Red
	$errorResponse = $ex.Response.GetResponseStream()
	$reader = New-Object System.IO.StreamReader($errorResponse)
	$reader.BaseStream.Position = 0
	$reader.DiscardBufferedData()
	$responseBody = $reader.ReadToEnd();
	Write-Host "Response content:`n$responseBody" -f Red
	Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
	write-host
	break

	}

}
	
####################################################

Function Get-InstallStatusForApp {

<#
.SYNOPSIS
This function will get the installation status of an application given the application's ID.
.DESCRIPTION
If you want to track your managed intune application installation stats as you roll them out in your environment, use this commandlet to get the insights.
.EXAMPLE
Get-InstallStatusForApp -AppId a1a2a-b1b2b3b4-c1c2c3c4
This will return the installation status of the application with the ID of a1a2a-b1b2b3b4-c1c2c3c4
.NOTES
NAME: Get-InstallStatusForApp
#>
	
[cmdletbinding()]

param
(
	[Parameter(Mandatory=$true)]
	[string]$AppId
)
	
	$graphApiVersion = "Beta"
	$Resource = "deviceAppManagement/mobileApps/$AppId/installSummary"
	
	try
	{

		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
	}
	
}

####################################################

Function Get-DeviceStatusForApp {

<#
.SYNOPSIS
This function will get the devices installation status of an application given the application's ID.
.DESCRIPTION
If you want to track your managed intune application installation stats as you roll them out in your environment, use this commandlet to get the insights.
.EXAMPLE
Get-DeviceStatusForApp -AppId a1a2a-b1b2b3b4-c1c2c3c4
This will return devices and their installation status of the application with the ID of a1a2a-b1b2b3b4-c1c2c3c4
.NOTES
NAME: Get-DeviceStatusForApp
#>
	
[cmdletbinding()]

param
(
	[Parameter(Mandatory=$true)]
	[string]$AppId
)
	
	$graphApiVersion = "Beta"
	$Resource = "deviceAppManagement/mobileApps/$AppId/deviceStatuses"
	
	try
	{

		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
	}
	
}

####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

	# Setting DateTime to Universal time to work in all timezones
	$DateTime = (Get-Date).ToUniversalTime()

	# If the authToken exists checking when it expires
	$TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

		if($TokenExpires -le 0){

		write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
		write-host

			# Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

			if($User -eq $null -or $User -eq ""){

			$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
			Write-Host

			}

		$global:authToken = Get-AuthToken -User $User

		}
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

	if($User -eq $null -or $User -eq ""){

	$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
	Write-Host

	}

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

####################################################

$Application = Get-IntuneApplication -Name "Microsoft Teams"

if($Application){

	Get-InstallStatusForApp -AppId $Application.ID

}


