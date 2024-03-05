<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

param
(
[parameter(Mandatory=$false)]
$DeviceName,
[parameter(Mandatory=$false)]
$UserPrincipalName

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
This gets information on Intune managed devices
.DESCRIPTION
This gets information on Intune managed devices
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

Function Get-AADUser(){

<#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser
#>

[cmdletbinding()]

param
(
    $userPrincipalName,
    $Property
)

# Defining Variables
$graphApiVersion = "v1.0"
$User_resource = "users"
    
    try {
        
        if($userPrincipalName -eq "" -or $userPrincipalName -eq $null){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if($Property -eq "" -or $Property -eq $null){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName"
            Write-Verbose $uri
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

            }

            else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName/$Property"
            Write-Verbose $uri
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

            }

        }
    
    }

    catch {

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

function Set-IntuneDevicePrimaryUser {

<#
.SYNOPSIS
This updates the Intune device primary user
.DESCRIPTION
This updates the Intune device primary user
.EXAMPLE
Set-IntuneDevicePrimaryUser
.NOTES
NAME: Set-IntuneDevicePrimaryUser
#>

[cmdletbinding()]

param
(
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
$IntuneDeviceId,
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
$userId
)
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices('$IntuneDeviceId')/users/`$ref"

    try {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        $userUri = "https://graph.microsoft.com/$graphApiVersion/users/" + $userId

        $id = "@odata.id"
        $JSON = @{ $id="$userUri" } | ConvertTo-Json -Compress

        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

	} catch {
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		throw "Set-IntuneDevicePrimaryUser error"
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

if(!$DeviceName){

    Write-Host
    write-host "Intune Device Name:" -f Yellow
    $DeviceName = Read-Host

}

if(!$UserPrincipalName){

    Write-Host
    write-host "User Principal Name:" -f Yellow
    $UserPrincipalName = Read-Host

}

$Device = Get-Win10IntuneManagedDevice -deviceName "$DeviceName"

if($Device){

    Write-Host "Device name:" $device."deviceName" -ForegroundColor Cyan
    $IntuneDevicePrimaryUser = Get-IntuneDevicePrimaryUser -deviceId $Device.id

    if($IntuneDevicePrimaryUser -eq $null){

        Write-Host "No Intune Primary User Id set for Intune Managed Device" $Device."deviceName" -f Red 

    }

    else {
    
        Write-Host "Intune Device Primary User:" $IntuneDevicePrimaryUser

    }

    $User = Get-AADUser -userPrincipalName $UserPrincipalName

    $AADUserName = $User.displayName
    
        if($IntuneDevicePrimaryUser -notmatch $User.id){

            $SetIntuneDevicePrimaryUser = Set-IntuneDevicePrimaryUser -IntuneDeviceId $Device.id -userId $User.id

            if($SetIntuneDevicePrimaryUser -eq ""){

                Write-Host "User"$User.displayName"set as Primary User for device '$DeviceName'..." -ForegroundColor Green

            }

        }

        else {

            Write-Host "The user '$AADUserName' specified is already the Primary User on the device..." -ForegroundColor Red

        }

}

else {

    Write-Host "Intune Device '$DeviceName' can't be found..." -ForegroundColor Red

}

Write-Host
