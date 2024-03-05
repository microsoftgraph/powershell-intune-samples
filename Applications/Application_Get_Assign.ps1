
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

Function Get-IntuneApplication(){

<#
.SYNOPSIS
This function is used to get applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any applications added
.EXAMPLE
Get-IntuneApplication
Returns any applications configured in Intune
.NOTES
NAME: Get-IntuneApplication
#>

[cmdletbinding()]

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps"
    
    try {
        
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value | ? { (!($_.'@odata.type').Contains("managed")) }

    }
    
    catch {

    $ex = $_.Exception
    Write-Host "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" -f Red
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

Function Get-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to get an application assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets an application assignment
.EXAMPLE
Get-ApplicationAssignment
Returns an Application Assignment configured in Intune
.NOTES
NAME: Get-ApplicationAssignment
#>

[cmdletbinding()]

param
(
    $ApplicationId
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/?`$expand=categories,assignments"
    
    try {
        
        if(!$ApplicationId){

        write-host "No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        else {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get)
        
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
    [ValidateSet("available", "required")]
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

$AssignedGroups = (Get-ApplicationAssignment -ApplicationId $ApplicationId).assignments

if($AssignedGroups){

$App_Count = @($AssignedGroups).count
$i = 1

    if($AssignedGroups.target.GroupId -contains $TargetGroupId){

        Write-Host "'$AADGroup' is already targetted to this application, can't add an AAD Group already assigned..." -f Red

    }

    else {

# Creating header of JSON File
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
    },
"@

# Looping through all existing assignments and adding them to the JSON object
foreach($Assignment in $AssignedGroups){

$ExistingTargetGroupId = $Assignment.target.GroupId
$ExistingInstallIntent = $Assignment.intent

$JSON += @"
    
    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$ExistingTargetGroupId"
      },
      "intent": "$ExistingInstallIntent"
"@

if($i -ne $App_Count){

$JSON += @"

    },

"@

}

else {

$JSON += @"

    }

"@

}

$i++

}

# Adding close of JSON object
$JSON += @"

    ]
}

"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

    }

}

else {

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
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value

        }
        
        elseif($GroupName -eq "" -or $GroupName -eq $null){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value
        
        }

        else {
            
            if(!$Members){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value
            
            }
            
            elseif($Members){
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            $Group = (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value
            
                if($Group){

                $GID = $Group.id

                $Group.displayName
                write-host

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value

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

# Setting AAD Group to assign application

$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where application will be assigned"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host

####################################################

# Display Name of the Application to add an assignment to
$ApplicationName = "IntuneApplication"

$Application = Get-IntuneApplication | ? { $_.displayName -eq "$ApplicationName" }

    if(@($Application).count -eq 1){

        $Application

        Add-ApplicationAssignment -ApplicationId $Application.id -TargetGroupId "$TargetGroupId" -InstallIntent required

    }

    else {

        Write-Host "There are" @($Application).count "applications with display Name '$ApplicationName'..." -ForegroundColor Red
        Write-Host

    }
