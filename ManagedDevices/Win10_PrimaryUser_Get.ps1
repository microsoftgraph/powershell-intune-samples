<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

param
(
[parameter(Mandatory=$false)]
$DeviceName

)

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

function Get-Win10IntuneManagedDevice {

<#
.SYNOPSIS
This gets information on Intune managed device
.DESCRIPTION
This gets information on Intune managed device
.EXAMPLE
Get-Win10IntuneManagedDevice
.NOTES
NAME: Get-Win10IntuneManagedDevice
#>

[cmdletbinding()]

param
(
[parameter(Mandatory=$false)]
[ValidateNotNullOrEmpty()]
[string]$deviceName
)
    
    $graphApiVersion = "beta"

    try {

        if($deviceName){

            $Resource = "deviceManagement/managedDevices?`$filter=deviceName eq '$deviceName'"
	        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)" 

            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

        }

        else {

            $Resource = "deviceManagement/managedDevices?`$filter=(((deviceType%20eq%20%27desktop%27)%20or%20(deviceType%20eq%20%27windowsRT%27)%20or%20(deviceType%20eq%20%27winEmbedded%27)%20or%20(deviceType%20eq%20%27surfaceHub%27)))"
	        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

        }

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw "Get-IntuneManagedDevices error"
	}

}

####################################################

function Get-AADDeviceId {

<#
.SYNOPSIS
This gets an AAD device object id from the Intune AAD device id
.DESCRIPTION
This gets an AAD device object id from the Intune AAD device id
.EXAMPLE
Get-AADDeviceId
.NOTES
NAME: Get-AADDeviceId
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string] $deviceId
)
    $graphApiVersion = "beta"
    $Resource = "devices"
	$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=deviceId eq '$deviceId'"

    try {
        $device = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        return $device.value."id"

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw "Get-AADDeviceId error"
	}
}

####################################################

function Get-IntuneDevicePrimaryUser {

<#
.SYNOPSIS
This lists the Intune device primary user
.DESCRIPTION
This lists the Intune device primary user
.EXAMPLE
Get-IntuneDevicePrimaryUser
.NOTES
NAME: Get-IntuneDevicePrimaryUser
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string] $deviceId
)
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"
	$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)" + "/" + $deviceId + "/users"

    try {
        
        $primaryUser = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        return $primaryUser.value."id"
        
	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw "Get-IntuneDevicePrimaryUser error"
	}
}

####################################################

function Get-AADDevicesRegisteredOwners {

<#
.SYNOPSIS
This lists the AAD devices registered owners
.DESCRIPTION
List of AAD device registered owners
.EXAMPLE
Get-AADDevicesRegisteredOwners
.NOTES
NAME: Get-AADDevicesRegisteredOwners
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string] $deviceId
)
    $graphApiVersion = "beta"
    $Resource = "devices"
	$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$deviceId/registeredOwners"

    try {
        
        $registeredOwners = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        Write-Host "AAD Registered Owner:" -ForegroundColor Yellow

        if(@($registeredOwners.value).count -ge 1){

            for($i=0; $i -lt $registeredOwners.value.Count; $i++){
            
                Write-Host "Id:" $registeredOwners.value[$i]."id"
                Write-Host "Name:" $registeredOwners.value[$i]."displayName"
            
            }

        }

        else {

            Write-Host "No registered Owner found in Azure Active Directory..." -ForegroundColor Red
        
        }

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw "Get-AADDevicesRegisteredOwners error"
	}
}

####################################################

function Get-AADDevicesRegisteredUsers {

<#
.SYNOPSIS
This lists the AAD devices registered users
.DESCRIPTION
List of AAD device registered users
.EXAMPLE
Get-AADDevicesRegisteredUsers
.NOTES
NAME: Get-AADDevicesRegisteredUsers
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string] $deviceId
)
    $graphApiVersion = "beta"
    $Resource = "devices"
	$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)" + "/$deviceId/registeredUsers"

    try {
        $registeredUsers = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        Write-Host "RegisteredUsers:" -ForegroundColor Yellow

        if(@($registeredUsers.value).count -ge 1){

            for($i=0; $i -lt $registeredUsers.value.Count; $i++)
            {

                Write-Host "Id:" $registeredUsers.value[$i]."id"
                Write-Host "Name:" $registeredUsers.value[$i]."displayName"
            }

        }

        else {

            Write-Host "No registered User found in Azure Active Directory..." -ForegroundColor Red
        
        }

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw "Get-AADDevicesRegisteredUsers error"
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

        # Defining User Principal Name if not present

        if($User -eq $null -or $User -eq ""){
            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host
        }

        $global:authToken = Get-AuthToken -User $User
    }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq "") {
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    }

    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
}

#endregion

####################################################

if($DeviceName){

    $Devices = Get-Win10IntuneManagedDevice -deviceName $DeviceName

}

else {

    $Devices = Get-Win10IntuneManagedDevice

}

####################################################

if($Devices){

    foreach($device in $Devices){

            Write-Host
            Write-Host "Device name:" $device."deviceName" -ForegroundColor Cyan
            Write-Host "Intune device id:" $device."id"
            
            $IntuneDevicePrimaryUser = Get-IntuneDevicePrimaryUser -deviceId $device.id

            if($IntuneDevicePrimaryUser -eq $null){

                Write-Host "No Intune Primary User Id set for Intune Managed Device" $Device."deviceName" -f Red 

            }

            else {

                Write-Host "Intune Primary user id:" $IntuneDevicePrimaryUser

            }

            $aadDeviceId = Get-AADDeviceId -deviceId $device."azureActiveDirectoryDeviceId"
            Write-Host
            Get-AADDevicesRegisteredOwners -deviceId $aadDeviceId
            Write-Host
            Get-AADDevicesRegisteredUsers -deviceId $aadDeviceId

            Write-Host
            Write-Host "-------------------------------------------------------------------"
    
    }

}

else {

    Write-Host "No Windows 10 devices found..." -ForegroundColor Red

}

Write-Host
