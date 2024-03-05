
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

Function Get-EndpointSecurityTemplate(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security templates using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Endpoint Security templates
.EXAMPLE
Get-EndpointSecurityTemplate 
Gets all Endpoint Security Templates in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityTemplate
#>


$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

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

Function Add-EndpointSecurityPolicy(){

<#
.SYNOPSIS
This function is used to add an Endpoint Security policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an Endpoint Security  policy
.EXAMPLE
Add-EndpointSecurityDiskEncryptionPolicy -JSON $JSON -TemplateId $templateId
Adds an Endpoint Security Policy in Endpoint Manager
.NOTES
NAME: Add-EndpointSecurityPolicy
#>

[cmdletbinding()]

param
(
    $TemplateId,
    $JSON
)

$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/templates/$TemplateId/createInstance"
Write-Verbose "Resource: $ESP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Endpoint Security Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

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
NAME: Test-JSON
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

$ImportPath = Read-Host -Prompt "Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Policies\policy.json"

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"','')

if(!(Test-Path "$ImportPath")){

Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
Write-Host "Script can't continue..." -ForegroundColor Red
Write-Host
break

}

####################################################

# Getting content of JSON Import file
$JSON_Data = gc "$ImportPath"

# Converting input to JSON format
$JSON_Convert = $JSON_Data | ConvertFrom-Json

# Pulling out variables to use in the import
$JSON_DN = $JSON_Convert.displayName
$JSON_TemplateDisplayName = $JSON_Convert.TemplateDisplayName
$JSON_TemplateId = $JSON_Convert.templateId

Write-Host
Write-Host "Endpoint Security Policy '$JSON_DN' found..." -ForegroundColor Cyan
Write-Host "Template Display Name: $JSON_TemplateDisplayName"
Write-Host "Template ID: $JSON_TemplateId"

####################################################

# Get all Endpoint Security Templates
$Templates = Get-EndpointSecurityTemplate

####################################################

# Checking if templateId from JSON is a valid templateId
$ES_Template = $Templates | ?  { $_.id -eq $JSON_TemplateId }

####################################################

# If template is a baseline Edge, MDATP or Windows, use templateId specified
if(($ES_Template.templateType -eq "microsoftEdgeSecurityBaseline") -or ($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")){

    $TemplateId = $JSON_Convert.templateId

}

####################################################

# Else If not a baseline, check if template is deprecated
elseif($ES_Template){

    # if template isn't deprecated use templateId
    if($ES_Template.isDeprecated -eq $false){

        $TemplateId = $JSON_Convert.templateId

    }

    # If template deprecated, look for lastest version
    elseif($ES_Template.isDeprecated -eq $true) {

        $Template = $Templates | ? { $_.displayName -eq "$JSON_TemplateDisplayName" }

        $Template = $Template | ? { $_.isDeprecated -eq $false }

        $TemplateId = $Template.id

    }

}

####################################################

# Else If Imported JSON template ID can't be found check if Template Display Name can be used
elseif($ES_Template -eq $null){

    Write-Host "Didn't find Template with ID $JSON_TemplateId, checking if Template DisplayName '$JSON_TemplateDisplayName' can be used..." -ForegroundColor Red
    $ES_Template = $Templates | ?  { $_.displayName -eq "$JSON_TemplateDisplayName" }

    If($ES_Template){

        if(($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")){

            Write-Host
            Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Red
            Write-Host "Importing using the updated template could fail as settings specified may not be included in the latest template..." -ForegroundColor Red
            Write-Host
            break

        }

        else {

            Write-Host "Template with displayName '$JSON_TemplateDisplayName' found..." -ForegroundColor Green

            $Template = $ES_Template | ? { $_.isDeprecated -eq $false }

            $TemplateId = $Template.id

        }

    }

    else {

        Write-Host
        Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Red
        Write-Host "Importing using the updated template could fail as settings specified may not be included in the latest template..." -ForegroundColor Red
        Write-Host
        break

    }

}

####################################################

# Excluding certain properties from JSON that aren't required for import
$JSON_Convert = $JSON_Convert | Select-Object -Property * -ExcludeProperty TemplateDisplayName,TemplateId,versionInfo

$DisplayName = $JSON_Convert.displayName

$JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5

write-host
$JSON_Output
write-host
Write-Host "Adding Endpoint Security Policy '$DisplayName'" -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $TemplateId -JSON $JSON_Output
