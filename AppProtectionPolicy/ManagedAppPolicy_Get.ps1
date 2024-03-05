
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

    $MethodArguments = [Type[]]@("System.String", "System.String", "System.Uri", "Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior", "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier")
    $NonAsync = $AuthContext.GetType().GetMethod("AcquireToken", $MethodArguments)

        if ($NonAsync -ne $null){

            $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, [Uri]$redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto, $userId)
        
        }
        
        else {

            $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, [Uri]$redirectUri, $platformParameters, $userId).Result 
        
        }

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

Function Get-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to get managed app policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app policies
.EXAMPLE
Get-ManagedAppPolicy
Returns any managed app policies configured in Intune
.NOTES
NAME: Get-ManagedAppPolicy
#>

[cmdletbinding()]

param
(
    $Name
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/managedAppPolicies"

    try {
    
        if($Name){
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }
    
        }
    
        else {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("ManagedAppProtection") -or ($_.'@odata.type').contains("InformationProtectionPolicy") }
    
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

Function Get-ManagedAppProtection(){

<#
.SYNOPSIS
This function is used to get managed app protection configuration from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app protection policy
.EXAMPLE
Get-ManagedAppProtection -id $id -OS "Android"
Returns a managed app protection policy for Android configured in Intune
Get-ManagedAppProtection -id $id -OS "iOS"
Returns a managed app protection policy for iOS configured in Intune
Get-ManagedAppProtection -id $id -OS "WIP_WE"
Returns a managed app protection policy for Windows 10 without enrollment configured in Intune
.NOTES
NAME: Get-ManagedAppProtection
#>

[cmdletbinding()]

param
(
    $id,
    $OS    
)

$graphApiVersion = "Beta"

    try {
    
        if($id -eq "" -or $id -eq $null){
    
        write-host "No Managed App Policy id specified, please provide a policy id..." -f Red
        break
    
        }
    
        else {
    
            if($OS -eq "" -or $OS -eq $null){
    
            write-host "No OS parameter specified, please provide an OS. Supported value are Android,iOS,WIP_WE,WIP_MDM..." -f Red
            Write-Host
            break
    
            }
    
            elseif($OS -eq "Android"){
    
            $Resource = "deviceAppManagement/androidManagedAppProtections('$id')/?`$expand=deploymentSummary,apps,assignments"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }
    
            elseif($OS -eq "iOS"){
    
            $Resource = "deviceAppManagement/iosManagedAppProtections('$id')/?`$expand=deploymentSummary,apps,assignments"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }

            elseif($OS -eq "WIP_WE"){
    
            $Resource = "deviceAppManagement/windowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }

            elseif($OS -eq "WIP_MDM"){
    
            $Resource = "deviceAppManagement/mdmWindowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

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

write-host "Running query against Microsoft Graph for App Protection Policies" -f Yellow

$ManagedAppPolicies = Get-ManagedAppPolicy

write-host

foreach($ManagedAppPolicy in $ManagedAppPolicies){

write-host "Managed App Policy:"$ManagedAppPolicy.displayName -f Yellow

$ManagedAppPolicy

    # If Android Managed App Policy
    
    if($ManagedAppPolicy.'@odata.type' -eq "#microsoft.graph.androidManagedAppProtection"){
    
        $AndroidManagedAppProtection = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "Android"
    
        write-host "Managed App Policy - Assignments" -f Cyan
    
        $AndroidAssignments = ($AndroidManagedAppProtection | select assignments).assignments
    
            if($AndroidAssignments){
    
                foreach($Group in $AndroidAssignments.target.groupId){
    
                (Get-AADGroup -id $Group).displayName
    
                }
    
                Write-Host
    
            }
    
            else {
    
            Write-Host "No assignments set for this policy..." -ForegroundColor Red
            Write-Host
    
            }
    
        write-host "Managed App Policy - Mobile Apps" -f Cyan
            
        if($ManagedAppPolicy.deployedAppCount -ge 1){
    
        ($AndroidManagedAppProtection | select apps).apps.mobileAppIdentifier
    
        }
    
        else {
    
        Write-Host "No Managed Apps targeted..." -ForegroundColor Red
        Write-Host
    
        }
    
    }

    # If iOS Managed App Policy
    
    elseif($ManagedAppPolicy.'@odata.type' -eq "#microsoft.graph.iosManagedAppProtection"){
    
        $iOSManagedAppProtection = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "iOS"
    
        write-host "Managed App Policy - Assignments" -f Cyan
    
        $iOSAssignments = ($iOSManagedAppProtection | select assignments).assignments
    
            if($iOSAssignments){
    
                foreach($Group in $iOSAssignments.target.groupId){
    
                (Get-AADGroup -id $Group).displayName
    
                }
    
                Write-Host
    
            }
    
            else {
    
            Write-Host "No assignments set for this policy..." -ForegroundColor Red
            Write-Host
    
            }
    
        write-host "Managed App Policy - Mobile Apps" -f Cyan
            
        if($ManagedAppPolicy.deployedAppCount -ge 1){
    
        ($iOSManagedAppProtection | select apps).apps.mobileAppIdentifier
    
        }
    
        else {
    
        Write-Host "No Managed Apps targeted..." -ForegroundColor Red
        Write-Host
    
        }
    
    }

    # If WIP Without Enrollment Managed App Policy
    
    elseif($ManagedAppPolicy.'@odata.type' -eq "#microsoft.graph.windowsInformationProtectionPolicy"){
    
        $Win10ManagedAppProtection = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "WIP_WE"
    
        write-host "Managed App Policy - Assignments" -f Cyan
    
        $Win10Assignments = ($Win10ManagedAppProtection | select assignments).assignments
    
            if($Win10Assignments){
    
                foreach($Group in $Win10Assignments.target.groupId){
    
                (Get-AADGroup -id $Group).displayName
    
                }
    
                Write-Host
    
            }
    
            else {
    
            Write-Host "No assignments set for this policy..." -ForegroundColor Red
            Write-Host
    
            }
    
        write-host "Protected Apps" -f Cyan
            
        if($Win10ManagedAppProtection.protectedApps){
    
        $Win10ManagedAppProtection.protectedApps.displayName
    
        Write-Host

        }
    
        else {
    
        Write-Host "No Protected Apps targeted..." -ForegroundColor Red
        Write-Host
    
        }

        
        write-host "Protected AppLocker Files" -ForegroundColor Cyan

        if($Win10ManagedAppProtection.protectedAppLockerFiles){
    
        $Win10ManagedAppProtection.protectedAppLockerFiles.displayName

        Write-Host
    
        }
    
        else {
    
        Write-Host "No Protected Applocker Files targeted..." -ForegroundColor Red
        Write-Host
    
        }
    
    }

    # If WIP with Enrollment (MDM) Managed App Policy
    
    elseif($ManagedAppPolicy.'@odata.type' -eq "#microsoft.graph.mdmWindowsInformationProtectionPolicy"){
    
        $Win10ManagedAppProtection = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "WIP_MDM"
    
        write-host "Managed App Policy - Assignments" -f Cyan
    
        $Win10Assignments = ($Win10ManagedAppProtection | select assignments).assignments
    
            if($Win10Assignments){
    
                foreach($Group in $Win10Assignments.target.groupId){
    
                (Get-AADGroup -id $Group).displayName
    
                }
    
                Write-Host
    
            }
    
            else {
    
            Write-Host "No assignments set for this policy..." -ForegroundColor Red
            Write-Host
    
            }
    
        write-host "Protected Apps" -f Cyan
            
        if($Win10ManagedAppProtection.protectedApps){
    
        $Win10ManagedAppProtection.protectedApps.displayName
    
        Write-Host

        }
    
        else {
    
        Write-Host "No Protected Apps targeted..." -ForegroundColor Red
        Write-Host
    
        }

        
        write-host "Protected AppLocker Files" -ForegroundColor Cyan

        if($Win10ManagedAppProtection.protectedAppLockerFiles){
    
        $Win10ManagedAppProtection.protectedAppLockerFiles.displayName

        Write-Host
    
        }
    
        else {
    
        Write-Host "No Protected Applocker Files targeted..." -ForegroundColor Red
        Write-Host
    
        }
    
    }

}
