﻿
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

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
 
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
 
$resourceAppIdURI = "https://graph.microsoft.com"
 
$authority = "https://login.windows.net/$Tenant"
 
    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "RefreshSession"

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

Function Set-IntuneBrand(){

<#
.SYNOPSIS
This function is used to set the Company Intune Brand resource using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets the Company Intune Brand Resource
.EXAMPLE
Set-IntuneBrand -id $id -JSON $JSON
Sets the Company Intune Brand using Graph API
.NOTES
NAME: Set-IntuneBrand
#>

[cmdletbinding()]

param
(
    $id,
    $JSON
)

$graphApiVersion = "Beta"
$App_resource = "organization('$id')"

    try {

        if(!$id){
        write-host "Organization Id hasn't been specified, please specify Id..." -f Red
        break
        }

        elseif(!$JSON){

        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Patch -ContentType "application/json" -Body $JSON -Headers $authToken

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

Function Get-Organization(){

<#
.SYNOPSIS
This function is used to get the Organization intune resource from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets the Organization Intune Resource
.EXAMPLE
Get-Organization
Returns the Organization resource configured in Intune
.NOTES
NAME: Get-Organization
#>

[cmdletbinding()]

$graphApiVersion = "Beta"
$resource = "organization"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
    (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value

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

Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $JSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-AuthHeader
#>

param (

$JSON

)

    try {

    $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
    $validJson = $true

    }

    catch {

    $validJson = $false
    $_.Exception

    }

    if (!$validJson){

    Write-Host "Provided JSON isn't in valid JSON format" -f Red
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

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

####################################################

$Org = Get-Organization

$id = $Org.id

####################################################

$iconUrl = "C:\Logos\Logo.png"

if(!(Test-Path "$iconUrl")){

Write-Host
write-host "Icon Path '$iconUrl' doesn't exist..." -ForegroundColor Red
write-host "Please specify a valid path to an icon..." -ForegroundColor Red
Write-Host
break

}

$iconResponse = Invoke-WebRequest "$iconUrl"
$base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
$iconExt = ([System.IO.Path]::GetExtension("$iconURL")).replace(".","")
$iconType = "image/$iconExt"

####################################################

$JSON_Logo = @"
{
    "intuneBrand":{
    "displayName": "IT Company",
    "contactITName": "IT Admin",
    "contactITPhoneNumber": "01234567890",
    "contactITEmailAddress": "admin@itcompany.com",
    "contactITNotes": "some notes go here",
    "privacyUrl": "http://itcompany.com",
    "onlineSupportSiteUrl": "http://www.itcompany.com",
    "onlineSupportSiteName": "IT Company Website",
    "themeColor": {"r":0,"g":114,"b":198},
    "showLogo": true,
    lightBackgroundLogo: {
        "type": "$iconType`;base",
        "value": "$base64icon"
          },
    darkBackgroundLogo: {
        "type": "$iconType`;base",
        "value": "$base64icon"
          },
    "showNameNextToLogo": false,
    "@odata.type":"#microsoft.management.services.api.intuneBrand"
    }
}
"@

####################################################

Set-IntuneBrand -id $id -JSON $JSON_Logo
