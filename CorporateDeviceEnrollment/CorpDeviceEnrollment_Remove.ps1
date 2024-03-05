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

Function Get-CorporateDeviceIdentifiers(){

<#
.SYNOPSIS
This function is used to get Corporate Device Identifiers from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets Corporate Device Identifiers
.EXAMPLE
Get-CorporateDeviceIdentifiers
Returns Corporate Device Identifiers configured in Intune
.NOTES
NAME: Get-CorporateDeviceIdentifiers
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$false)]
    $DeviceIdentifier
)


$graphApiVersion = "beta"

    try {

        if($DeviceIdentifier){

            $Resource = "deviceManagement/importedDeviceIdentities?`$filter=contains(importedDeviceIdentifier,'$DeviceIdentifier')"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        }

        else {

            $Resource = "deviceManagement/importedDeviceIdentities"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        }

    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

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

Function Remove-CorporateDeviceIdentifier(){

<#
.SYNOPSIS
This function is used to remove a Corporate Device Identifier from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and removes a Corporate Device Identifier
.EXAMPLE
Remove-CorporateDeviceIdentifier -ImportedDeviceId "123456789012345"
Removes Corporate Device Identifier with that Id configured in Intune
.NOTES
NAME: Remove-CorporateDeviceIdentifier
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $ImportedDeviceId
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/importedDeviceIdentities/$ImportedDeviceId"

    try {

    write-host "Are you sure you want to delete selected device information? Y or N?" -ForegroundColor Yellow
    write-host "It will not affect devices already enrolled in Intune." -ForegroundColor Yellow

    $Confirm = read-host

        if($Confirm -eq "y" -or $Confirm -eq "Y"){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete

        }

        else {

            Write-Host "Deletion of the Device Identifier from Intune for the device was cancelled..." -ForegroundColor Gray
            Write-Host

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

$CDI = Get-CorporateDeviceIdentifiers -DeviceIdentifier "123456789012345"

if(@($CDI).count -eq 1){

    $CDI_Id = $CDI.id
    $CDI_Identifier = $CDI.importedDeviceIdentifier

    Write-Host "DeviceId:" $CDI_Id
    Write-Host "Imported Device Identifier:" $CDI_Identifier
    Write-Host
    
    Remove-CorporateDeviceIdentifier -ImportedDeviceId $CDI_Id

}

else {

    Write-Host "More than one device was found with that Device Identifier," -ForegroundColor Red
    Write-Host "or the Device Identifier wasn't found in the Intune Service..." -ForegroundColor Red
    Write-Host

}

