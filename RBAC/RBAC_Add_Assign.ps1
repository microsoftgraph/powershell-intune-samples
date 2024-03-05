
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

Function Add-RBACRole(){

<#
.SYNOPSIS
This function is used to add an RBAC Role Definitions from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an RBAC Role Definitions
.EXAMPLE
Add-RBACRole -JSON $JSON
.NOTES
NAME: Add-RBACRole
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/roleDefinitions"
    
    try {

        if(!$JSON){

        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }

        Test-JSON -JSON $JSON
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $Json -ContentType "application/json"
    
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

Function Assign-RBACRole(){

<#
.SYNOPSIS
This function is used to set an assignment for an RBAC Role using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets and assignment for an RBAC Role
.EXAMPLE
Assign-RBACRole -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupId $MemberGroupId -TargetGroupId $TargetGroupId
Creates and Assigns and Intune Role assignment to an Intune Role in Intune
.NOTES
NAME: Assign-RBACRole
#>

[cmdletbinding()]

param
(
    $Id,
    $DisplayName,
    $MemberGroupId,
    $TargetGroupId
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/roleAssignments"
    
    try {

        if(!$Id){

        write-host "No Policy Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$DisplayName){

        write-host "No Display Name specified, specify a Display Name" -f Red
        break

        }

        if(!$MemberGroupId){

        write-host "No Member Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }


$JSON = @"

    {
    "id":"",
    "description":"",
    "displayName":"$DisplayName",
    "members":["$MemberGroupId"],
    "scopeMembers":["$TargetGroupId"],
    "roleDefinition@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$ID')"
    }

"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
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

# Setting Member AAD Group

$MemberAADGroup = Read-Host -Prompt "Enter the Azure AD Group name for Intune Role Members"

$MemberGroupId = (get-AADGroup -GroupName "$MemberAADGroup").id

    if($MemberGroupId -eq $null -or $MemberGroupId -eq ""){

    Write-Host "AAD Group - '$MemberAADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host

####################################################

# Setting Scope AAD Group

$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name for Intune Role Scope"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host

####################################################

$JSON = @"

{
  "@odata.type": "#microsoft.graph.roleDefinition",
  "displayName": "Graph RBAC Role Assigned",
  "description": "New RBAC Role Description",
  "permissions": [
    {
      "actions": [
        "Microsoft.Intune/MobileApps/Read",
        "Microsoft.Intune/TermsAndConditions/Read",
        "Microsoft.Intune/ManagedApps/Read",
        "Microsoft.Intune/ManagedDevices/Read",
        "Microsoft.Intune/DeviceConfigurations/Read",
        "Microsoft.Intune/TelecomExpenses/Read",
        "Microsoft.Intune/Organization/Read",
        "Microsoft.Intune/RemoteTasks/RebootNow",
        "Microsoft.Intune/RemoteTasks/RemoteLock"
      ]
    }
  ],
  "isBuiltInRoleDefinition": false
}

"@

####################################################

Write-Host "Adding Intune Role from JSON..." -ForegroundColor Yellow
Write-Host "Creating Intune Role via Graph"
$CreateResult = Add-RBACRole -JSON $JSON
write-host "Intune Role created with id" $CreateResult.id

$IntuneRoleID = $CreateResult.id

Write-Host

Write-Host "Creating Intune Role Assignment..." -ForegroundColor Yellow
Write-Host "Creating Intune Role Assignment via Graph"

$AssignmentIntuneRole = Assign-RBACRole -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupId $MemberGroupId -TargetGroupId $TargetGroupId
write-host "Intune Role Assigment created with id" $AssignmentIntuneRole.id

Write-Host
