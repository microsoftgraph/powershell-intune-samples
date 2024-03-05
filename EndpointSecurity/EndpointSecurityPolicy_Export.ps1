
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

Function Get-EndpointSecurityPolicy(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security policies using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Endpoint Security templates
.EXAMPLE
Get-EndpointSecurityPolicy
Gets all Endpoint Security Policies in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityPolicy
#>


$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/intents"

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

Function Get-EndpointSecurityTemplateCategory(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security categories from a specific template using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all template categories
.EXAMPLE
Get-EndpointSecurityTemplateCategory -TemplateId $templateId
Gets an Endpoint Security Categories from a specific template in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityTemplateCategory
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $TemplateId
)

$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/templates/$TemplateId/categories"

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

Function Get-EndpointSecurityCategorySetting(){

<#
.SYNOPSIS
This function is used to get an Endpoint Security category setting from a specific policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a policy category setting
.EXAMPLE
Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
Gets an Endpoint Security Categories from a specific template in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityCategory
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $PolicyId,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $categoryId
)

$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/intents/$policyId/categories/$categoryId/settings?`$expand=Microsoft.Graph.DeviceManagementComplexSettingInstance/Value"

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

Function Export-JSONData(){

<#
.SYNOPSIS
This function is used to export JSON data returned from Graph
.DESCRIPTION
This function is used to export JSON data returned from Graph
.EXAMPLE
Export-JSONData -JSON $JSON
Export the JSON inputted on the function
.NOTES
NAME: Export-JSONData
#>

param (

$JSON,
$ExportPath

)

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON..." -f Red

        }

        elseif(!$ExportPath){

        write-host "No export path parameter set, please provide a path to export the file" -f Red

        }

        elseif(!(Test-Path $ExportPath)){

        write-host "$ExportPath doesn't exist, can't export JSON Data" -f Red

        }

        else {

        $JSON1 = ConvertTo-Json $JSON -Depth 5

        $JSON_Convert = $JSON1 | ConvertFrom-Json

        $displayName = $JSON_Convert.displayName

        # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
        $DisplayName = $DisplayName -replace '\<|\>|:|"|/|\\|\||\?|\*', "_"

            # Added milliseconds to date format due to duplicate policy name
            $FileName_JSON = "$DisplayName" + "_" + $(get-date -f dd-MM-yyyy-H-mm-ss.fff) + ".json"

            write-host "Export Path:" "$ExportPath"

            $JSON1 | Set-Content -LiteralPath "$ExportPath\$FileName_JSON"
            write-host "JSON created in $ExportPath\$FileName_JSON..." -f cyan
            
        }

    }

    catch {

    $_.Exception

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

#region ExportPath

$ExportPath = Read-Host -Prompt "Please specify a path to export the policy data to e.g. C:\IntuneOutput"

    # If the directory path doesn't exist prompt user to create the directory
    $ExportPath = $ExportPath.replace('"','')

    if(!(Test-Path "$ExportPath")){

    Write-Host
    Write-Host "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow

    $Confirm = read-host

        if($Confirm -eq "y" -or $Confirm -eq "Y"){

        new-item -ItemType Directory -Path "$ExportPath" | Out-Null
        Write-Host

        }

        else {

        Write-Host "Creation of directory path was cancelled..." -ForegroundColor Red
        Write-Host
        break

        }

    }

Write-Host

#endregion

####################################################

# Get all Endpoint Security Templates
$Templates = Get-EndpointSecurityTemplate

####################################################

# Get all Endpoint Security Policies configured
$ESPolicies = Get-EndpointSecurityPolicy | Sort-Object displayName

####################################################

# Looping through all policies configured
foreach($policy in $ESPolicies){

    Write-Host "Endpoint Security Policy:"$policy.displayName -ForegroundColor Yellow
    $PolicyName = $policy.displayName
    $PolicyDescription = $policy.description
    $policyId = $policy.id
    $TemplateId = $policy.templateId
    $roleScopeTagIds = $policy.roleScopeTagIds

    $ES_Template = $Templates | ?  { $_.id -eq $policy.templateId }

    $TemplateDisplayName = $ES_Template.displayName
    $TemplateId = $ES_Template.id
    $versionInfo = $ES_Template.versionInfo

    if($TemplateDisplayName -eq "Endpoint detection and response"){

        Write-Host "Export of 'Endpoint detection and response' policy not included in sample script..." -ForegroundColor Magenta
        Write-Host

    }

    else {

        ####################################################

        # Creating object for JSON output
        $JSON = New-Object -TypeName PSObject

        Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'displayName' -Value "$PolicyName"
        Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'description' -Value "$PolicyDescription"
        Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'roleScopeTagIds' -Value $roleScopeTagIds
        Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'TemplateDisplayName' -Value "$TemplateDisplayName"
        Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'TemplateId' -Value "$TemplateId"
        Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'versionInfo' -Value "$versionInfo"

        ####################################################

        # Getting all categories in specified Endpoint Security Template
        $Categories = Get-EndpointSecurityTemplateCategory -TemplateId $TemplateId

        # Looping through all categories within the Template

        foreach($category in $Categories){

            $categoryId = $category.id

            $Settings += Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
        
        }

        # Adding All settings to settingsDelta ready for JSON export
        Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'settingsDelta' -Value @($Settings)

        ####################################################

        Export-JSONData -JSON $JSON -ExportPath "$ExportPath"

        Write-Host

        # Clearing up variables so previous data isn't exported in each policy
        Clear-Variable JSON
        Clear-Variable Settings

    }

}
