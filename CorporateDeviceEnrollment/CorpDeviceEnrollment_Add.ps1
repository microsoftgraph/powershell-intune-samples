
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

Function Add-CorporateDeviceIdentifiers(){

<#
.SYNOPSIS
This function is used to add a Corporate Device Identifier from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a Corporate Device Identifier
.EXAMPLE
Add-CorporateDeviceIdentifiers -IdentifierType imei -OverwriteImportedDeviceIdentities false -Identifier "12345678901234" -Description "Device Information"
Adds a Corporate Device Identifier to Intune
.NOTES
NAME: Add-CorporateDeviceIdentifiers
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [ValidateSet("imei","serialNumber")]
    $IdentifierType,
    [Parameter(Mandatory=$true)]
    [ValidateSet("false","true")]
    $OverwriteImportedDeviceIdentities,
    [Parameter(Mandatory=$true)]
    $Identifier,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Description
)


$graphApiVersion = "beta"
$Resource = "deviceManagement/importedDeviceIdentities/importDeviceIdentityList"

    try {

$JSON = @"

{
"overwriteImportedDeviceIdentities": $OverwriteImportedDeviceIdentities,
"importedDeviceIdentities": [ { 
"importedDeviceIdentifier": "$Identifier",
"importedDeviceIdentityType": "$IdentifierType",
"description": "$Description"}
]
}

"@

        if($IdentifierType -eq "imei"){

            if(($Identifier -match "^[0-9]+$") -and ($Identifier.length -ge 15)){

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken).value

            }

            elseif($Identifier -notmatch "^[0-9]+$" -or ($Identifier.length -lt 15)) {

                Write-Host "Invalid Device Identifier '$Identifier' parameter found for $IdentifierType Identity Type..." -ForegroundColor Red

            }

        }

        if($IdentifierType -eq "serialNumber"){

            if(($Identifier -match "^[a-zA-Z0-9]+$") -and (@($Description).length -le 128)){

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken).value

            }

            elseif($Identifier -notmatch "^[a-zA-Z0-9]+$"){

                Write-Host "Invalid Device Identifier '$Identifier' parameter found for $IdentifierType Identity Type..." -ForegroundColor Red

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
    $line = $_.InvocationInfo.ScriptLineNumber
    $msg = $ex.message
    $ErrorMessage += "$responseBody`n"
    $ErrorMessage += "Exception: $msg on line $line"
    Write-Error $ErrorMessage
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

$Status = Add-CorporateDeviceIdentifiers -IdentifierType imei -OverwriteImportedDeviceIdentities false -Identifier "123456789012345" -Description "Test Device"

if($Status.status -eq $true) {

    Write-Host "Device" $status.importedDeviceIdentifier "added to the Intune Service..." -ForegroundColor Green
    $Status

}

elseif($Status.status -eq $false) {

    Write-Host "Device" $status.importedDeviceIdentifier "import failed, the device identifier could have already been added to the service..." -ForegroundColor Red

}

Write-Host
