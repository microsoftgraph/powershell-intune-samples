
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
.REFERENCE
Acknowledgement to Paolo Marques
https://blogs.technet.microsoft.com/paulomarques/2016/03/21/working-with-azure-active-directory-graph-api-from-powershell/

#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $TenantName
)
 
$adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
 
$adalforms = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
 
    if((test-path "$adal") -eq $false){
 
    write-host
    write-host "Azure Powershell module not installed..." -f Red
    write-host "Please install Azure SDK for Powershell - https://azure.microsoft.com/en-us/downloads/" -f Yellow
    write-host "Script can't continue..." -f Red
    write-host
    exit
 
    }
 
[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
 
[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
 
$clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
 
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
 
$resourceAppIdURI = "https://graph.microsoft.com"
 
$authority = "https://login.windows.net/$TenantName"
 
    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
 
    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $authResult = $authContext.AcquireToken($resourceAppIdURI,$clientId,$redirectUri, "Always")

        # Building Rest Api header with authorization token
        $authHeader = @{
        'Content-Type'='application\json'
        'Authorization'=$authResult.CreateAuthorizationHeader()
        'ExpiresOn'=$authResult.ExpiresOn
        }

    return $authHeader

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

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if($tenant -eq $null -or $tenant -eq ""){

            $tenant = Read-Host -Prompt "Please specify your tenant name"
            Write-Host

            }

        $global:authToken = Get-AuthToken -TenantName $tenant

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($tenant -eq $null -or $tenant -eq ""){

    # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

    $tenant = Read-Host -Prompt "Please specify your tenant name"

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -TenantName $tenant

}

#endregion

####################################################

$Org = Get-Organization

$id = $Org.id

####################################################

$JSON_Default = @"

{

    "intuneBrand":{
    "displayName":null,
    "contactITName":null,
    "contactITPhoneNumber":null,
    "contactITEmailAddress":null,
    "contactITNotes":null,
    "privacyUrl":null,
    "onlineSupportSiteUrl":null,
    "onlineSupportSiteName":null,
    "themeColor":{"r":0,"g":114,"b":198},
    "showLogo":false,
    "showNameNextToLogo":false,
    "lightBackgroundLogo":null,
    "darkBackgroundLogo":null,
    "@odata.type":"#microsoft.management.services.api.intuneBrand"
    }

}

"@

####################################################

Set-IntuneBrand -id $id -JSON $JSON_Default
