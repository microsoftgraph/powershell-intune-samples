
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>


param (
    [parameter(Mandatory=$false)]
    [string]$OnboardingXMLFilePath,
    [parameter(Mandatory=$false)]
    [string]$AADGroup
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

Function Add-MDMApplication(){

<#
.SYNOPSIS
This function is used to add an MDM application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an MDM application from the itunes store
.EXAMPLE
Add-MDMApplication -JSON $JSON
Adds an application into Intune
.NOTES
NAME: Add-MDMApplication
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

    try {

        if(!$JSON){

        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken

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

Function Add-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>

[cmdletbinding()]

param
(
    $ApplicationId,
    $TargetGroupId,
    $InstallIntent
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
    
    try {

        if(!$ApplicationId){

        write-host "No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        
        if(!$InstallIntent){

        write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
        break

        }

$JSON = @"

{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
    }
    ]
}

"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

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

Function Add-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $JSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"
Write-Verbose "Resource: $DCP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
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

Function Add-DeviceConfigurationPolicyAssignment(){

<#
.SYNOPSIS
This function is used to add a device configuration policy assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy assignment
.EXAMPLE
Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
Adds a device configuration policy assignment in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicyAssignment
#>

[cmdletbinding()]

param
(
    $ConfigurationPolicyId,
    $TargetGroupId
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assign"
    
    try {

        if(!$ConfigurationPolicyId){

        write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        $ConfPolAssign = "$ConfigurationPolicyId" + "_" + "$TargetGroupId"

$JSON = @"

{
  "deviceConfigurationGroupAssignments": [
    {
      "@odata.type": "#microsoft.graph.deviceConfigurationGroupAssignment",
      "id": "$ConfPolAssign",
      "targetGroupId": "$TargetGroupId"
    }
  ]
}

"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

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

Function Get-AADGroup(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup
#>

[cmdletbinding()]

param
(
    $GroupName,
    $id,
    [switch]$Members
)

# Defining Variables
$graphApiVersion = "v1.0"
$Group_resource = "groups"
    
    try {

        if($id){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=id eq '$id'"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }
        
        elseif($GroupName -eq "" -or $GroupName -eq $null){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if(!$Members){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
            }
            
            elseif($Members){
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            $Group = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
                if($Group){

                $GID = $Group.id

                $Group.displayName
                write-host

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                }

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
#
# Look for WindowsDefenderATPOnboarding.xml file
#
####################################################

if (!($OnboardingXMLFilePath)){

    do {

        $OnboardingXMLFilePath = Read-Host -Prompt "Enter path to your WindowsDefenderATPOnboarding.XML File"
        
        if (!(Test-Path $OnboardingXMLFilePath)){

            write-host " - Couldn't find $OnboardingXMLFilePath, try again" -f yellow
        
        }

    }

    until (Test-Path $OnboardingXMLFilePath)

}

else {

    if (!(Test-Path $OnboardingXMLFilePath)){

        write-host " - Couldn't find $OnboardingXMLFilePath, please run script again with a valid path" -f yellow
        Write-Host
        break
    }

}

$OnboardingXMLFile = get-content "$OnboardingXMLFilePath" -Encoding byte
$OnboardingXML = [System.Convert]::ToBase64String($OnboardingXMLFile)

####################################################

$MDATP_Onboarding  = @"
{
    "@odata.type":  "#microsoft.graph.macOSCustomConfiguration",
    "description":  "",
    "displayName":  "macOS MDATP Onboarding",
    "payloadName":  "MDATP Onboarding",
    "payloadFileName":  "WindowsDefenderATPOnboarding.xml",
    "payload":  "$OnboardingXML"
}
"@

####################################################

$MDATP_FullDiskAccess  = @"
{

    "@odata.type":  "#microsoft.graph.macOSCustomConfiguration",
    "description":  "",
    "displayName":  "macOS MDATP Full Disk Access",
    "payloadName":  "macOS MDATP Full Disk Access",
    "payloadFileName":  "FullDiskAccess.xml",
    "payload":  "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KICAgIDxrZXk+UGF5bG9hZERlc2NyaXB0aW9uPC9rZXk+CiAgICA8c3RyaW5nPkFsbG93cyBNaWNyb3NvZnQgRGVmZW5kZXIgdG8gYWNjZXNzIGFsbCBmaWxlcyBvbiBDYXRhbGluYSs8L3N0cmluZz4KICAgIDxrZXk+UGF5bG9hZERpc3BsYXlOYW1lPC9rZXk+CiAgICA8c3RyaW5nPlRDQyAtIE1pY3Jvc29mdCBEZWZlbmRlcjwvc3RyaW5nPgogICAgPGtleT5QYXlsb2FkSWRlbnRpZmllcjwva2V5PgogICAgPHN0cmluZz5jb20ubWljcm9zb2Z0LndkYXYudGNjPC9zdHJpbmc+CiAgICA8a2V5PlBheWxvYWRPcmdhbml6YXRpb248L2tleT4KICAgIDxzdHJpbmc+TWljcm9zb2Z0IENvcnAuPC9zdHJpbmc+CiAgICA8a2V5PlBheWxvYWRSZW1vdmFsRGlzYWxsb3dlZDwva2V5PgogICAgPGZhbHNlLz4KICAgIDxrZXk+UGF5bG9hZFNjb3BlPC9rZXk+CiAgICA8c3RyaW5nPnN5c3RlbTwvc3RyaW5nPgogICAgPGtleT5QYXlsb2FkVHlwZTwva2V5PgogICAgPHN0cmluZz5Db25maWd1cmF0aW9uPC9zdHJpbmc+CiAgICA8a2V5PlBheWxvYWRVVUlEPC9rZXk+CiAgICA8c3RyaW5nPkMyMzRERjJFLURGRjYtMTFFOS1CMjc5LTAwMUM0Mjk5RkI0NDwvc3RyaW5nPgogICAgPGtleT5QYXlsb2FkVmVyc2lvbjwva2V5PgogICAgPGludGVnZXI+MTwvaW50ZWdlcj4KICAgIDxrZXk+UGF5bG9hZENvbnRlbnQ8L2tleT4KICAgIDxhcnJheT4KICAgIDxkaWN0PgogICAgICAgIDxrZXk+UGF5bG9hZERlc2NyaXB0aW9uPC9rZXk+CiAgICAgICAgPHN0cmluZz5BbGxvd3MgTWljcm9zb2Z0IERlZmVuZGVyIHRvIGFjY2VzcyBhbGwgZmlsZXMgb24gQ2F0YWxpbmErPC9zdHJpbmc+CiAgICAgICAgPGtleT5QYXlsb2FkRGlzcGxheU5hbWU8L2tleT4KICAgICAgICA8c3RyaW5nPlRDQyAtIE1pY3Jvc29mdCBEZWZlbmRlcjwvc3RyaW5nPgogICAgICAgIDxrZXk+UGF5bG9hZElkZW50aWZpZXI8L2tleT4KICAgICAgICA8c3RyaW5nPmNvbS5taWNyb3NvZnQud2Rhdi50Y2MuQzIzM0E1RTYtREZGNi0xMUU5LUJEQUQtMDAxQzQyOTlGQjQ0PC9zdHJpbmc+CiAgICAgICAgPGtleT5QYXlsb2FkT3JnYW5pemF0aW9uPC9rZXk+CiAgICAgICAgPHN0cmluZz5NaWNyb3NvZnQgQ29ycC48L3N0cmluZz4KICAgICAgICA8a2V5PlBheWxvYWRUeXBlPC9rZXk+CiAgICAgICAgPHN0cmluZz5jb20uYXBwbGUuVENDLmNvbmZpZ3VyYXRpb24tcHJvZmlsZS1wb2xpY3k8L3N0cmluZz4KICAgICAgICA8a2V5PlBheWxvYWRVVUlEPC9rZXk+CiAgICAgICAgPHN0cmluZz5DMjMzQTVFNi1ERkY2LTExRTktQkRBRC0wMDFDNDI5OUZCNDQ8L3N0cmluZz4KICAgICAgICA8a2V5PlBheWxvYWRWZXJzaW9uPC9rZXk+CiAgICAgICAgPGludGVnZXI+MTwvaW50ZWdlcj4KICAgICAgICA8a2V5PlNlcnZpY2VzPC9rZXk+CiAgICAgICAgPGRpY3Q+CiAgICAgICAgICAgIDxrZXk+U3lzdGVtUG9saWN5QWxsRmlsZXM8L2tleT4KICAgICAgICAgICAgPGFycmF5PgogICAgICAgICAgICA8ZGljdD4KICAgICAgICAgICAgICAgIDxrZXk+QWxsb3dlZDwva2V5PgogICAgICAgICAgICAgICAgPHRydWUvPgogICAgICAgICAgICAgICAgPGtleT5Db2RlUmVxdWlyZW1lbnQ8L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+aWRlbnRpZmllciAiY29tLm1pY3Jvc29mdC53ZGF2IiBhbmQgYW5jaG9yIGFwcGxlIGdlbmVyaWMgYW5kIGNlcnRpZmljYXRlIDFbZmllbGQuMS4yLjg0MC4xMTM2MzUuMTAwLjYuMi42XSAvKiBleGlzdHMgKi8gYW5kIGNlcnRpZmljYXRlIGxlYWZbZmllbGQuMS4yLjg0MC4xMTM2MzUuMTAwLjYuMS4xM10gLyogZXhpc3RzICovIGFuZCBjZXJ0aWZpY2F0ZSBsZWFmW3N1YmplY3QuT1VdID0gVUJGOFQzNDZHOTwvc3RyaW5nPgogICAgICAgICAgICAgICAgPGtleT5Db21tZW50PC9rZXk+CiAgICAgICAgICAgICAgICA8c3RyaW5nPkFsbG93IFN5c3RlbVBvbGljeUFsbEZpbGVzIGNvbnRyb2wgZm9yIE1pY3Jvc29mdCBEZWZlbmRlciBBVFA8L3N0cmluZz4KICAgICAgICAgICAgICAgIDxrZXk+SWRlbnRpZmllcjwva2V5PgogICAgICAgICAgICAgICAgPHN0cmluZz5jb20ubWljcm9zb2Z0LndkYXY8L3N0cmluZz4KICAgICAgICAgICAgICAgIDxrZXk+SWRlbnRpZmllclR5cGU8L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+YnVuZGxlSUQ8L3N0cmluZz4KICAgICAgICAgICAgPC9kaWN0PgogICAgICAgICAgICA8L2FycmF5PgogICAgICAgIDwvZGljdD4KICAgIDwvZGljdD4KICAgIDwvYXJyYXk+CjwvZGljdD4KPC9wbGlzdD4K"

}
"@

####################################################

$MDATP_Kext  = @"
{
    "@odata.type":  "#microsoft.graph.macOSCustomConfiguration",
    "description":  "",
    "displayName":  "macOS MDATP Kernel Extension",
    "payloadName":  "macOS MDATP Kernel Extension",
    "payloadFileName":  "kext.xml",
    "payload":  "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjwhRE9DVFlQRSBwbGlzdCBQVUJMSUMgIi0vL0FwcGxlLy9EVEQgUExJU1QgMS4wLy9FTiIgImh0dHA6Ly93d3cuYXBwbGUuY29tL0RURHMvUHJvcGVydHlMaXN0LTEuMC5kdGQiPg0KPHBsaXN0IHZlcnNpb249IjEiPg0KICAgIDxkaWN0Pg0KICAgICAgICA8a2V5PlBheWxvYWRVVUlEPC9rZXk+DQogICAgICAgIDxzdHJpbmc+NTA1REI4NDAtMUY0NC00OTg0LUI4RTYtMkVGRjBCNDVCNjdBPC9zdHJpbmc+DQogICAgICAgIDxrZXk+UGF5bG9hZFR5cGU8L2tleT4NCiAgICAgICAgPHN0cmluZz5Db25maWd1cmF0aW9uPC9zdHJpbmc+DQogICAgICAgIDxrZXk+UGF5bG9hZE9yZ2FuaXphdGlvbjwva2V5Pg0KICAgICAgICA8c3RyaW5nPk1pY3Jvc29mdDwvc3RyaW5nPg0KICAgICAgICA8a2V5PlBheWxvYWRJZGVudGlmaWVyPC9rZXk+DQogICAgICAgIDxzdHJpbmc+NTA1REI4NDAtMUY0NC00OTg0LUI4RTYtMkVGRjBCNDVCNjdBPC9zdHJpbmc+DQogICAgICAgIDxrZXk+UGF5bG9hZERpc3BsYXlOYW1lPC9rZXk+DQogICAgICAgIDxzdHJpbmc+QXBwcm92ZWQgS2VybmVsIEV4dGVuc2lvbnM8L3N0cmluZz4NCiAgICAgICAgPGtleT5QYXlsb2FkRGVzY3JpcHRpb248L2tleT4NCiAgICAgICAgPHN0cmluZz5UaGlzIHByb2ZpbGUgY29uZmlndXJlcyB5b3VyIE1hYyB0byBhdXRvbWF0aWNhbGx5IGVuYWJsZSB0aGlyZC1wYXJ0eSBrZXJuZWwgZXh0ZW5zaW9ucyBmcm9tIHNwZWNpZmllZCB2ZW5kb3JzLjwvc3RyaW5nPg0KICAgICAgICA8a2V5PlBheWxvYWRWZXJzaW9uPC9rZXk+DQogICAgICAgIDxpbnRlZ2VyPjE8L2ludGVnZXI+DQogICAgICAgIDxrZXk+UGF5bG9hZEVuYWJsZWQ8L2tleT4NCiAgICAgICAgPHRydWUvPg0KICAgICAgICA8a2V5PlBheWxvYWRSZW1vdmFsRGlzYWxsb3dlZDwva2V5Pg0KICAgICAgICA8dHJ1ZS8+DQogICAgICAgIDxrZXk+UGF5bG9hZFNjb3BlPC9rZXk+DQogICAgICAgIDxzdHJpbmc+U3lzdGVtPC9zdHJpbmc+DQogICAgICAgIDxrZXk+UGF5bG9hZENvbnRlbnQ8L2tleT4NCiAgICAgICAgPGFycmF5Pg0KICAgICAgICAgICAgPGRpY3Q+DQogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkVVVJRDwva2V5Pg0KICAgICAgICAgICAgICAgIDxzdHJpbmc+MzdDNjI0NDItNURENy00Q0Y1LThGRDktRjkwQ0Y2QzRGMUJCPC9zdHJpbmc+DQogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkVHlwZTwva2V5Pg0KICAgICAgICAgICAgICAgIDxzdHJpbmc+Y29tLmFwcGxlLnN5c3BvbGljeS5rZXJuZWwtZXh0ZW5zaW9uLXBvbGljeTwvc3RyaW5nPg0KICAgICAgICAgICAgICAgIDxrZXk+UGF5bG9hZE9yZ2FuaXphdGlvbjwva2V5Pg0KICAgICAgICAgICAgICAgIDxzdHJpbmc+TWljcm9zb2Z0PC9zdHJpbmc+DQogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkSWRlbnRpZmllcjwva2V5Pg0KICAgICAgICAgICAgICAgIDxzdHJpbmc+MzdDNjI0NDItNURENy00Q0Y1LThGRDktRjkwQ0Y2QzRGMUJCPC9zdHJpbmc+DQogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkRGlzcGxheU5hbWU8L2tleT4NCiAgICAgICAgICAgICAgICA8c3RyaW5nPkFwcHJvdmVkIEtlcm5lbCBFeHRlbnNpb25zPC9zdHJpbmc+DQogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkRGVzY3JpcHRpb248L2tleT4NCiAgICAgICAgICAgICAgICA8c3RyaW5nLz4NCiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWRWZXJzaW9uPC9rZXk+DQogICAgICAgICAgICAgICAgPGludGVnZXI+MTwvaW50ZWdlcj4NCiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWRFbmFibGVkPC9rZXk+DQogICAgICAgICAgICAgICAgPHRydWUvPg0KICAgICAgICAgICAgICAgIDxrZXk+QWxsb3dVc2VyT3ZlcnJpZGVzPC9rZXk+DQogICAgICAgICAgICAgICAgPHRydWUvPg0KICAgICAgICAgICAgICAgIDxrZXk+QWxsb3dlZFRlYW1JZGVudGlmaWVyczwva2V5Pg0KICAgICAgICAgICAgICAgIDxhcnJheT4NCiAgICAgICAgICAgICAgICAgICAgPHN0cmluZz5VQkY4VDM0Nkc5PC9zdHJpbmc+DQogICAgICAgICAgICAgICAgPC9hcnJheT4NCiAgICAgICAgICAgIDwvZGljdD4NCiAgICAgICAgPC9hcnJheT4NCiAgICA8L2RpY3Q+DQo8L3BsaXN0Pg=="
}
"@

####################################################

$MDATP = @"

{
  "@odata.type": "#microsoft.graph.macOSMdatpApp",
  "description": "Microsoft Defender Advanced Threat Protection (Microsoft Defender ATP) is a unified platform for preventative protection, post-breach detection, automated investigation, and response. Microsoft Defender ATP protects endpoints from cyber threats; detects advanced attacks and data breaches, automates security incidents and improves security posture.",
  "developer": "Microsoft",
  "displayName": "macOS Microsoft Defender ATP for macOS",
  "informationUrl": "https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/microsoft-defender-advanced-threat-protection​",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "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"
  },
  "notes": "",
  "owner": "Microsoft",
  "privacyInformationUrl": "https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/mac-privacy​",
  "publisher": "Microsoft"
}

"@

####################################################

$MDATP_Notifications = @"

{
    "@odata.type":  "#microsoft.graph.macOSCustomConfiguration",
    "description":  "",
    "displayName":  "macOS MDATP Notifications",
    "payloadName":  "macOS MDATP Notifications",
    "payloadFileName":  "mdatp.notifications.xml",
    "payload":  "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgogIDxkaWN0PgogICAgPGtleT5QYXlsb2FkQ29udGVudDwva2V5PgogICAgPGFycmF5PgogICAgICA8ZGljdD4KICAgICAgICA8a2V5Pk5vdGlmaWNhdGlvblNldHRpbmdzPC9rZXk+CiAgICAgICAgPGFycmF5PgogICAgICAgICAgPGRpY3Q+CiAgICAgICAgICAgIDxrZXk+QWxlcnRUeXBlPC9rZXk+CiAgICAgICAgICAgIDxpbnRlZ2VyPjI8L2ludGVnZXI+CiAgICAgICAgICAgIDxrZXk+QmFkZ2VzRW5hYmxlZDwva2V5PgogICAgICAgICAgICA8dHJ1ZS8+CiAgICAgICAgICAgIDxrZXk+QnVuZGxlSWRlbnRpZmllcjwva2V5PgogICAgICAgICAgICA8c3RyaW5nPmNvbS5taWNyb3NvZnQuYXV0b3VwZGF0ZTI8L3N0cmluZz4KICAgICAgICAgICAgPGtleT5Dcml0aWNhbEFsZXJ0RW5hYmxlZDwva2V5PgogICAgICAgICAgICA8ZmFsc2UvPgogICAgICAgICAgICA8a2V5Pkdyb3VwaW5nVHlwZTwva2V5PgogICAgICAgICAgICA8aW50ZWdlcj4wPC9pbnRlZ2VyPgogICAgICAgICAgICA8a2V5Pk5vdGlmaWNhdGlvbnNFbmFibGVkPC9rZXk+CiAgICAgICAgICAgIDx0cnVlLz4KICAgICAgICAgICAgPGtleT5TaG93SW5Mb2NrU2NyZWVuPC9rZXk+CiAgICAgICAgICAgIDxmYWxzZS8+CiAgICAgICAgICAgIDxrZXk+U2hvd0luTm90aWZpY2F0aW9uQ2VudGVyPC9rZXk+CiAgICAgICAgICAgIDx0cnVlLz4KICAgICAgICAgICAgPGtleT5Tb3VuZHNFbmFibGVkPC9rZXk+CiAgICAgICAgICAgIDx0cnVlLz4KICAgICAgICAgIDwvZGljdD4KICAgICAgICAgIDxkaWN0PgogICAgICAgICAgICA8a2V5PkFsZXJ0VHlwZTwva2V5PgogICAgICAgICAgICA8aW50ZWdlcj4yPC9pbnRlZ2VyPgogICAgICAgICAgICA8a2V5PkJhZGdlc0VuYWJsZWQ8L2tleT4KICAgICAgICAgICAgPHRydWUvPgogICAgICAgICAgICA8a2V5PkJ1bmRsZUlkZW50aWZpZXI8L2tleT4KICAgICAgICAgICAgPHN0cmluZz5jb20ubWljcm9zb2Z0LndkYXZ0cmF5PC9zdHJpbmc+CiAgICAgICAgICAgIDxrZXk+Q3JpdGljYWxBbGVydEVuYWJsZWQ8L2tleT4KICAgICAgICAgICAgPGZhbHNlLz4KICAgICAgICAgICAgPGtleT5Hcm91cGluZ1R5cGU8L2tleT4KICAgICAgICAgICAgPGludGVnZXI+MDwvaW50ZWdlcj4KICAgICAgICAgICAgPGtleT5Ob3RpZmljYXRpb25zRW5hYmxlZDwva2V5PgogICAgICAgICAgICA8dHJ1ZS8+CiAgICAgICAgICAgIDxrZXk+U2hvd0luTG9ja1NjcmVlbjwva2V5PgogICAgICAgICAgICA8ZmFsc2UvPgogICAgICAgICAgICA8a2V5PlNob3dJbk5vdGlmaWNhdGlvbkNlbnRlcjwva2V5PgogICAgICAgICAgICA8dHJ1ZS8+CiAgICAgICAgICAgIDxrZXk+U291bmRzRW5hYmxlZDwva2V5PgogICAgICAgICAgICA8dHJ1ZS8+CiAgICAgICAgICA8L2RpY3Q+CiAgICAgICAgPC9hcnJheT4KICAgICAgICA8a2V5PlBheWxvYWREZXNjcmlwdGlvbjwva2V5PgogICAgICAgIDxzdHJpbmcvPgogICAgICAgIDxrZXk+UGF5bG9hZERpc3BsYXlOYW1lPC9rZXk+CiAgICAgICAgPHN0cmluZz5ub3RpZmljYXRpb25zPC9zdHJpbmc+CiAgICAgICAgPGtleT5QYXlsb2FkRW5hYmxlZDwva2V5PgogICAgICAgIDx0cnVlLz4KICAgICAgICA8a2V5PlBheWxvYWRJZGVudGlmaWVyPC9rZXk+CiAgICAgICAgPHN0cmluZz5CQjk3NzMxNS1FNENCLTQ5MTUtOTBDNy04MzM0Qzc1QTdDNjQ8L3N0cmluZz4KICAgICAgICA8a2V5PlBheWxvYWRPcmdhbml6YXRpb248L2tleT4KICAgICAgICA8c3RyaW5nPk1pY3Jvc29mdDwvc3RyaW5nPgogICAgICAgIDxrZXk+UGF5bG9hZFR5cGU8L2tleT4KICAgICAgICA8c3RyaW5nPmNvbS5hcHBsZS5ub3RpZmljYXRpb25zZXR0aW5nczwvc3RyaW5nPgogICAgICAgIDxrZXk+UGF5bG9hZFVVSUQ8L2tleT4KICAgICAgICA8c3RyaW5nPkJCOTc3MzE1LUU0Q0ItNDkxNS05MEM3LTgzMzRDNzVBN0M2NDwvc3RyaW5nPgogICAgICAgIDxrZXk+UGF5bG9hZFZlcnNpb248L2tleT4KICAgICAgICA8aW50ZWdlcj4xPC9pbnRlZ2VyPgogICAgICA8L2RpY3Q+CiAgICA8L2FycmF5PgogICAgPGtleT5QYXlsb2FkRGVzY3JpcHRpb248L2tleT4KICAgIDxzdHJpbmcvPgogICAgPGtleT5QYXlsb2FkRGlzcGxheU5hbWU8L2tleT4KICAgIDxzdHJpbmc+bWRhdHAgLSBhbGxvdyBub3RpZmljYXRpb25zPC9zdHJpbmc+CiAgICA8a2V5PlBheWxvYWRFbmFibGVkPC9rZXk+CiAgICA8dHJ1ZS8+CiAgICA8a2V5PlBheWxvYWRJZGVudGlmaWVyPC9rZXk+CiAgICA8c3RyaW5nPjg1RjY4MDVCLTAxMDYtNEQyMy05MTAxLTdGMURGRDVFQTZENjwvc3RyaW5nPgogICAgPGtleT5QYXlsb2FkT3JnYW5pemF0aW9uPC9rZXk+CiAgICA8c3RyaW5nPk1pY3Jvc29mdDwvc3RyaW5nPgogICAgPGtleT5QYXlsb2FkUmVtb3ZhbERpc2FsbG93ZWQ8L2tleT4KICAgIDxmYWxzZS8+CiAgICA8a2V5PlBheWxvYWRTY29wZTwva2V5PgogICAgPHN0cmluZz5TeXN0ZW08L3N0cmluZz4KICAgIDxrZXk+UGF5bG9hZFR5cGU8L2tleT4KICAgIDxzdHJpbmc+Q29uZmlndXJhdGlvbjwvc3RyaW5nPgogICAgPGtleT5QYXlsb2FkVVVJRDwva2V5PgogICAgPHN0cmluZz44NUY2ODA1Qi0wMTA2LTREMjMtOTEwMS03RjFERkQ1RUE2RDY8L3N0cmluZz4KICAgIDxrZXk+UGF5bG9hZFZlcnNpb248L2tleT4KICAgIDxpbnRlZ2VyPjE8L2ludGVnZXI+CiAgPC9kaWN0Pgo8L3BsaXN0Pgo="
}

"@

####################################################


$MDATP_sysext = @"

{
    "@odata.type":  "#microsoft.graph.macOSCustomConfiguration",
     "description":  "Approves required system extension for Defender AT on macOS, for Big Sur and newer",
    "displayName":  "macOS MDATP System Extension",
    "payloadName":  "MDATP macOS System Extension",
    "payloadFileName":  "system extension.xml",
    "payload":  "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48IURPQ1RZUEUgcGxpc3QgUFVCTElDICItLy9BcHBsZS8vRFREIFBMSVNUIDEuMC8vRU4iICJodHRwOi8vd3d3LmFwcGxlLmNvbS9EVERzL1Byb3BlcnR5TGlzdC0xLjAuZHRkIj4KPHBsaXN0IHZlcnNpb249IjEiPgogICAgPGRpY3Q+CiAgICAgICAgPGtleT5QYXlsb2FkVVVJRDwva2V5PgogICAgICAgIDxzdHJpbmc+N0U1M0FDNTAtQjg4RC00MTMyLTk5QjYtMjlGNzk3NEVBQTNDPC9zdHJpbmc+CiAgICAgICAgPGtleT5QYXlsb2FkVHlwZTwva2V5PgogICAgICAgIDxzdHJpbmc+Q29uZmlndXJhdGlvbjwvc3RyaW5nPgogICAgICAgIDxrZXk+UGF5bG9hZE9yZ2FuaXphdGlvbjwva2V5PgogICAgICAgIDxzdHJpbmc+TWljcm9zb2Z0IENvcnBvcmF0aW9uPC9zdHJpbmc+CiAgICAgICAgPGtleT5QYXlsb2FkSWRlbnRpZmllcjwva2V5PgogICAgICAgIDxzdHJpbmc+N0U1M0FDNTAtQjg4RC00MTMyLTk5QjYtMjlGNzk3NEVBQTNDPC9zdHJpbmc+CiAgICAgICAgPGtleT5QYXlsb2FkRGlzcGxheU5hbWU8L2tleT4KICAgICAgICA8c3RyaW5nPk1pY3Jvc29mdCBEZWZlbmRlciBBVFAgU3lzdGVtIEV4dGVuc2lvbnM8L3N0cmluZz4KICAgICAgICA8a2V5PlBheWxvYWREZXNjcmlwdGlvbjwva2V5PgogICAgICAgIDxzdHJpbmcvPgogICAgICAgIDxrZXk+UGF5bG9hZFZlcnNpb248L2tleT4KICAgICAgICA8aW50ZWdlcj4xPC9pbnRlZ2VyPgogICAgICAgIDxrZXk+UGF5bG9hZEVuYWJsZWQ8L2tleT4KICAgICAgICA8dHJ1ZS8+CiAgICAgICAgPGtleT5QYXlsb2FkUmVtb3ZhbERpc2FsbG93ZWQ8L2tleT4KICAgICAgICA8dHJ1ZS8+CiAgICAgICAgPGtleT5QYXlsb2FkU2NvcGU8L2tleT4KICAgICAgICA8c3RyaW5nPlN5c3RlbTwvc3RyaW5nPgogICAgICAgIDxrZXk+UGF5bG9hZENvbnRlbnQ8L2tleT4KICAgICAgICA8YXJyYXk+CiAgICAgICAgICAgIDxkaWN0PgogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkVVVJRDwva2V5PgogICAgICAgICAgICAgICAgPHN0cmluZz4yQkEwNzBEOS0yMjMzLTQ4MjctQUZDMS0xRjQ0QzhDOEU1Mjc8L3N0cmluZz4KICAgICAgICAgICAgICAgIDxrZXk+UGF5bG9hZFR5cGU8L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+Y29tLmFwcGxlLndlYmNvbnRlbnQtZmlsdGVyPC9zdHJpbmc+CiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWRPcmdhbml6YXRpb248L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+TWljcm9zb2Z0IENvcnBvcmF0aW9uPC9zdHJpbmc+CiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWRJZGVudGlmaWVyPC9rZXk+CiAgICAgICAgICAgICAgICA8c3RyaW5nPkNFQkY3QTcxLUQ5QTEtNDhCRC04Q0NGLUJEOUQxOEVDMTU1QTwvc3RyaW5nPgogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkRGlzcGxheU5hbWU8L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+QXBwcm92ZWQgTmV0d29yayBFeHRlbnNpb248L3N0cmluZz4KICAgICAgICAgICAgICAgIDxrZXk+UGF5bG9hZERlc2NyaXB0aW9uPC9rZXk+CiAgICAgICAgICAgICAgICA8c3RyaW5nLz4KICAgICAgICAgICAgICAgIDxrZXk+UGF5bG9hZFZlcnNpb248L2tleT4KICAgICAgICAgICAgICAgIDxpbnRlZ2VyPjE8L2ludGVnZXI+CiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWRFbmFibGVkPC9rZXk+CiAgICAgICAgICAgICAgICA8dHJ1ZS8+CiAgICAgICAgICAgICAgICA8a2V5PkZpbHRlclR5cGU8L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+UGx1Z2luPC9zdHJpbmc+CiAgICAgICAgICAgICAgICA8a2V5PlVzZXJEZWZpbmVkTmFtZTwva2V5PgogICAgICAgICAgICAgICAgPHN0cmluZz5NaWNyb3NvZnQgRGVmZW5kZXIgQVRQIE5ldHdvcmsgRXh0ZW5zaW9uPC9zdHJpbmc+CiAgICAgICAgICAgICAgICA8a2V5PlBsdWdpbkJ1bmRsZUlEPC9rZXk+CiAgICAgICAgICAgICAgICA8c3RyaW5nPmNvbS5taWNyb3NvZnQud2Rhdjwvc3RyaW5nPgogICAgICAgICAgICAgICAgPGtleT5GaWx0ZXJTb2NrZXRzPC9rZXk+CiAgICAgICAgICAgICAgICA8dHJ1ZS8+CiAgICAgICAgICAgICAgICA8a2V5PkZpbHRlckRhdGFQcm92aWRlckJ1bmRsZUlkZW50aWZpZXI8L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+Y29tLm1pY3Jvc29mdC53ZGF2Lm5ldGV4dDwvc3RyaW5nPgogICAgICAgICAgICAgICAgPGtleT5GaWx0ZXJEYXRhUHJvdmlkZXJEZXNpZ25hdGVkUmVxdWlyZW1lbnQ8L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+aWRlbnRpZmllciAmcXVvdDtjb20ubWljcm9zb2Z0LndkYXYubmV0ZXh0JnF1b3Q7IGFuZCBhbmNob3IgYXBwbGUgZ2VuZXJpYyBhbmQgY2VydGlmaWNhdGUgMVtmaWVsZC4xLjIuODQwLjExMzYzNS4xMDAuNi4yLjZdIC8qIGV4aXN0cyAqLyBhbmQgY2VydGlmaWNhdGUgbGVhZltmaWVsZC4xLjIuODQwLjExMzYzNS4xMDAuNi4xLjEzXSAvKiBleGlzdHMgKi8gYW5kIGNlcnRpZmljYXRlIGxlYWZbc3ViamVjdC5PVV0gPSBVQkY4VDM0Nkc5PC9zdHJpbmc+CiAgICAgICAgICAgIDwvZGljdD4KICAgICAgICAgICAgPGRpY3Q+CiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWRVVUlEPC9rZXk+CiAgICAgICAgICAgICAgICA8c3RyaW5nPjU2MTA1RTg5LUM3QzgtNEE5NS1BRUU2LUUxMUI4QkVBMDM2Njwvc3RyaW5nPgogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkVHlwZTwva2V5PgogICAgICAgICAgICAgICAgPHN0cmluZz5jb20uYXBwbGUuVENDLmNvbmZpZ3VyYXRpb24tcHJvZmlsZS1wb2xpY3k8L3N0cmluZz4KICAgICAgICAgICAgICAgIDxrZXk+UGF5bG9hZE9yZ2FuaXphdGlvbjwva2V5PgogICAgICAgICAgICAgICAgPHN0cmluZz5NaWNyb3NvZnQgQ29ycG9yYXRpb248L3N0cmluZz4KICAgICAgICAgICAgICAgIDxrZXk+UGF5bG9hZElkZW50aWZpZXI8L2tleT4KICAgICAgICAgICAgICAgIDxzdHJpbmc+NTYxMDVFODktQzdDOC00QTk1LUFFRTYtRTExQjhCRUEwMzY2PC9zdHJpbmc+CiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWREaXNwbGF5TmFtZTwva2V5PgogICAgICAgICAgICAgICAgPHN0cmluZz5Qcml2YWN5IFByZWZlcmVuY2VzIFBvbGljeSBDb250cm9sPC9zdHJpbmc+CiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWREZXNjcmlwdGlvbjwva2V5PgogICAgICAgICAgICAgICAgPHN0cmluZy8+CiAgICAgICAgICAgICAgICA8a2V5PlBheWxvYWRWZXJzaW9uPC9rZXk+CiAgICAgICAgICAgICAgICA8aW50ZWdlcj4xPC9pbnRlZ2VyPgogICAgICAgICAgICAgICAgPGtleT5QYXlsb2FkRW5hYmxlZDwva2V5PgogICAgICAgICAgICAgICAgPHRydWUvPgogICAgICAgICAgICAgICAgPGtleT5TZXJ2aWNlczwva2V5PgogICAgICAgICAgICAgICAgPGRpY3Q+CiAgICAgICAgICAgICAgICAgICAgPGtleT5TeXN0ZW1Qb2xpY3lBbGxGaWxlczwva2V5PgogICAgICAgICAgICAgICAgICAgIDxhcnJheT4KICAgICAgICAgICAgICAgICAgICAgICAgPGRpY3Q+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8a2V5PklkZW50aWZpZXI8L2tleT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzdHJpbmc+Y29tLm1pY3Jvc29mdC53ZGF2LmVwc2V4dDwvc3RyaW5nPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGtleT5Db2RlUmVxdWlyZW1lbnQ8L2tleT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzdHJpbmc+aWRlbnRpZmllciAiY29tLm1pY3Jvc29mdC53ZGF2LmVwc2V4dCIgYW5kIGFuY2hvciBhcHBsZSBnZW5lcmljIGFuZCBjZXJ0aWZpY2F0ZSAxW2ZpZWxkLjEuMi44NDAuMTEzNjM1LjEwMC42LjIuNl0gLyogZXhpc3RzICovIGFuZCBjZXJ0aWZpY2F0ZSBsZWFmW2ZpZWxkLjEuMi44NDAuMTEzNjM1LjEwMC42LjEuMTNdIC8qIGV4aXN0cyAqLyBhbmQgY2VydGlmaWNhdGUgbGVhZltzdWJqZWN0Lk9VXSA9IFVCRjhUMzQ2Rzk8L3N0cmluZz4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxrZXk+SWRlbnRpZmllclR5cGU8L2tleT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzdHJpbmc+YnVuZGxlSUQ8L3N0cmluZz4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxrZXk+U3RhdGljQ29kZTwva2V5PgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGludGVnZXI+MDwvaW50ZWdlcj4KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxrZXk+QWxsb3dlZDwva2V5PgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGludGVnZXI+MTwvaW50ZWdlcj4KICAgICAgICAgICAgICAgICAgICAgICAgPC9kaWN0PgogICAgICAgICAgICAgICAgICAgIDwvYXJyYXk+CiAgICAgICAgICAgICAgICA8L2RpY3Q+CiAgICAgICAgICAgIDwvZGljdD4KICAgICAgICA8L2FycmF5PgogICAgPC9kaWN0Pgo8L3BsaXN0Pgo="
}

"@

####################################################

# Setting application AAD Group to assign Policy

do {
    
    if(!($AADGroup)){
    
        $AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where apps and policies will be assigned"
    
    }

    $TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

        Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor yellow
        $AADGroup = $null
    
    }

}

until ($TargetGroupId)

####################################################

write-host

write-host "Publishing" ($MDATP | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Application = Add-MDMApplication -JSON $MDATP

Write-Host " + Application created as $($Create_Application.displayName)/$($create_Application.id)"

$ApplicationId = $Create_Application.id

$Assign_Application = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent "required"
Write-Host " + Assigned '$AADGroup' to $($Create_Application.displayName)/$($Create_Application.id) with" $Assign_Application.InstallIntent "install Intent" -f cyan

Write-Host

####################################################

Write-Host "Adding MDATP Notification settings from JSON..." -ForegroundColor Yellow

$CreateResult_Notifications = Add-DeviceConfigurationPolicy -JSON $MDATP_Notifications

Write-Host " + Device WDATP Notifications Policy created as" $CreateResult_Notifications.id
write-host " + Assigning WDATP Notifications Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_kext = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_Notifications.id -TargetGroupId $TargetGroupId

Write-Host " + Assigned '$AADGroup' to $($CreateResult_Notificationst.displayName)/$($CreateResult_Notifications.id)"
Write-Host

####################################################

Write-Host "Adding MDATP Kext Policy from JSON..." -ForegroundColor Yellow

$CreateResult_Kext = Add-DeviceConfigurationPolicy -JSON $MDATP_Kext

Write-Host " + Device WDATP Kext Policy created as" $CreateResult_kext.id
write-host " + Assigning WDATP Kext Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_kext = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_kext.id -TargetGroupId $TargetGroupId

Write-Host " + Assigned '$AADGroup' to $($CreateResult_kext.displayName)/$($CreateResult_kext.id)"
Write-Host

####################################################

Write-Host "Adding MDATP Full Disk Access Policy from JSON..." -ForegroundColor Yellow

$CreateResult_FullDiskAccess = Add-DeviceConfigurationPolicy -JSON $MDATP_FullDiskAccess

Write-Host " + Device WDATP Full Disk Access Policy created as" $CreateResult_FullDiskAccess.id
write-host " + Assigning WDATP Full Disk Access Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_FullDiskAccess = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_FullDiskAccess.id -TargetGroupId $TargetGroupId

Write-Host " + Assigned '$AADGroup' to $($CreateResult_FullDiskAccess.displayName)/$($CreateResult_FullDiskAccess.id)"
Write-Host


####################################################

Write-Host "Adding MDATP OnBoarding Policy from XML..." -ForegroundColor Yellow

$CreateResult_Onboarding = Add-DeviceConfigurationPolicy -JSON $MDATP_Onboarding

Write-Host " + Device WDATP OnBoarding Policy created as" $CreateResult_Onboarding.id
write-host " + Assigning WDATP OnBoarding Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_Onboarding = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_Onboarding.id -TargetGroupId $TargetGroupId

Write-Host " + Assigned '$AADGroup' to $($CreateResult_Onboarding.displayName)/$($CreateResult_Onboarding.id)"
Write-Host

####################################################

Write-Host "Adding MDATP System Extension Policy from XML..." -ForegroundColor Yellow

$CreateResult_sysext = Add-DeviceConfigurationPolicy -JSON $MDATP_sysext

Write-Host " + Device WDATP System Extension Policy created as" $CreateResult_sysext.id
write-host " + Assigning WDATP System Extension Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_sysext = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_sysext.id -TargetGroupId $TargetGroupId

Write-Host " + Assigned '$AADGroup' to $($CreateResult_sysext.displayName)/$($CreateResult_sysext.id)"
Write-Host
