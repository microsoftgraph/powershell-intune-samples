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

Function Get-AADUser(){

<#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser
#>

[cmdletbinding()]

param
(
    $userPrincipalName,
    $Property
)

# Defining Variables
$graphApiVersion = "v1.0"
$User_resource = "users"
    
    try {
        
        if($userPrincipalName -eq "" -or $userPrincipalName -eq $null){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if($Property -eq "" -or $Property -eq $null){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName"
            Write-Verbose $uri
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

            }

            else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName/$Property"
            Write-Verbose $uri
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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

Function Get-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to get managed app policies (AppConfig) from the Graph API REST interface
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
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/managedAppPolicies"

    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("ManagedAppProtection") -or ($_.'@odata.type').contains("InformationProtectionPolicy") }
    
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
    
            write-host "No OS parameter specified, please provide an OS. Supported values are Android,iOS, and Windows..." -f Red
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

            elseif($OS -eq "Windows"){
    
            $Resource = "deviceAppManagement/windowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    
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
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assignments"

    try {

        if(!$ApplicationId){

        write-host "No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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

Function Get-MobileAppConfigurations(){
    
<#
.SYNOPSIS
This function is used to get all Mobile App Configuration Policies (managed device) using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Mobile App Configuration Policies from the itunes store
.EXAMPLE
Get-MobileAppConfigurations
Gets all Mobile App Configuration Policies configured in the Intune Service
.NOTES
NAME: Get-MobileAppConfigurations
#>

[cmdletbinding()]
    
$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
        
    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

    (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken).value


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

Function Get-TargetedManagedAppConfigurations(){
    
<#
.SYNOPSIS
This function is used to get all Targeted Managed App Configuration Policies using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Targeted Managed App Configuration Policies from the itunes store
.EXAMPLE
Get-TargetedManagedAppConfigurations
Gets all Targeted Managed App Configuration Policies configured in the Intune Service
.NOTES
NAME: Get-TargetedManagedAppConfigurations
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$false)]
    $PolicyId
)
    
$graphApiVersion = "Beta"
        
    try {

        if($PolicyId){

            $Resource = "deviceAppManagement/targetedManagedAppConfigurations('$PolicyId')?`$expand=apps,assignments"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken)

        }

        else {

            $Resource = "deviceAppManagement/targetedManagedAppConfigurations"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken).value

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

param
(
    $id,
    $Name
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps"

    try {

        if($id){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)

        }
        
        
        elseif($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") -and (!($_.'@odata.type').Contains("managed")) }

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { (!($_.'@odata.type').Contains("managed")) }

        }

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

Function Get-IntuneMAMApplication(){

<#
.SYNOPSIS
This function is used to get MAM applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any MAM applications
.EXAMPLE
Get-IntuneMAMApplication
Returns any MAM applications configured in Intune
.NOTES
NAME: Get-IntuneMAMApplication
#>

[cmdletbinding()]

param
(
$packageid,
$bundleid
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps"

    try {

        if($packageid){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains("managed") -and ($_.'appAvailability' -eq "Global") -and ($_.'packageid' -eq "$packageid") }

        }

        elseif($bundleid){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains("managed") -and ($_.'appAvailability' -eq "Global") -and ($_.'bundleid' -eq "$bundleid") }

        }

        else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains("managed") -and ($_.'appAvailability' -eq "Global") }

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

write-host "This script outputs the Intune app protection policies and application configuration policies assigned to a user."
Write-Host

Write-Warning "This script doesn't support configurations applied to nested group members"

Write-Host
write-host "Enter the UPN:" -f Yellow
$UPN = Read-Host

if($UPN -eq $null -or $UPN -eq ""){

    write-host "User Principal Name is Null..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break

}

$User = Get-AADUser -userPrincipalName $UPN

if(!$User){ break }

$UserID = $User.id

write-host
write-host "-------------------------------------------------------------------"
Write-Host
write-host "Display Name:"$User.displayName
write-host "User Principal Name:"$User.userPrincipalName
Write-Host
write-host "-------------------------------------------------------------------"
write-host

####################################################

$OSChoices = "Android","iOS"

#region menu

$OSChoicesCount = "2"

    $menu = @{}

    for ($i=1;$i -le $OSChoices.count; $i++) 
    { Write-Host "$i. $($OSChoices[$i-1])" 
    $menu.Add($i,($OSChoices[$i-1]))}

    Write-Host
    $ans = Read-Host 'Choose an OS (numerical value)'

    if($ans -eq "" -or $ans -eq $null){

    Write-Host "OS choice can't be null, please specify a valid OS..." -ForegroundColor Red
    Write-Host
    break

    }

    elseif(($ans -match "^[\d\.]+$") -eq $true){

    $selection = $menu.Item([int]$ans)

        if($selection){

            $OS = $OSChoices | ? { $_ -eq "$Selection" }

        }

        else {

            Write-Host "OS choice selection invalid, please specify a valid OS..." -ForegroundColor Red
            Write-Host
            break

        }

    }

    else {

        Write-Host "OS choice not an integer, please specify a valid OS..." -ForegroundColor Red
        Write-Host
        break

    }

    Write-Host

#endregion

$MemberOf = Get-AADUser -userPrincipalName $UPN -Property MemberOf

$AADGroups = $MemberOf | ? { $_.'@odata.type' -eq "#microsoft.graph.group" }

####################################################

#region App Protection Policies

write-host "-------------------------------------------------------------------"
Write-Host
Write-Host "App Protection Policies: $OS" -ForegroundColor Cyan
Write-Host
write-host "-------------------------------------------------------------------"
Write-Host

$ManagedAppPolicies = Get-ManagedAppPolicy | ? {$_.'@odata.type' -like "*$os*"}

if($ManagedAppPolicies){

$AssignmentCount = 0

    foreach($ManagedAppPolicy in $ManagedAppPolicies){

        # If Android Managed App Policy
    
        if($ManagedAppPolicy.'@odata.type' -eq "#microsoft.graph.androidManagedAppProtection"){

            $AndroidManagedAppProtection = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "Android"
            
            $MAMApps = $AndroidManagedAppProtection.apps

            $AndroidAssignments = ($AndroidManagedAppProtection | select assignments).assignments
    
            if($AndroidAssignments){
    
                foreach($Group in $AndroidAssignments.target){

                    if($AADGroups.id -contains $Group.groupId){

                    $AssignmentCount++

                    $GroupID = $Group.GroupId
                    $GroupTargetType = $Group.'@odata.type'.split(".")[-1]

                    $targetedAppManagementLevels = $AndroidManagedAppProtection.targetedAppManagementLevels

                        switch ($targetedAppManagementLevels){

                            "unspecified" {$ManagementType = "All app types";break}
                            "mdm" {$ManagementType = "Apps on managed devices";break}
                            "unmanaged" {$ManagementType = "Apps on unmanaged devices";break}

                            }

                    write-host "Policy name: " -NoNewline
                    write-host $AndroidManagedAppProtection.displayname -ForegroundColor Green
                    write-host "Group assigned: " -NoNewline
                    write-host (get-aadgroup -id $GroupID).displayname

                    if($GroupTargetType -eq "exclusionGroupAssignmentTarget"){
                    
                        Write-Host "Group Target: " -NoNewline
                        Write-Host "Excluded" -ForegroundColor Red
                    
                    }

                    elseif($GroupTargetType -eq "GroupAssignmentTarget"){
                    
                        Write-Host "Group Target: " -NoNewline
                        Write-Host "Included" -ForegroundColor Green
                    
                    }

                    Write-Host
                    Write-Host "Targeted Apps:" -ForegroundColor Yellow

                    foreach($MAMApp in $MAMApps){

                        $AppName = (Get-IntuneMAMApplication -packageId $MAMApp.mobileAppIdentifier.packageId).displayName

                        if($AppName){ $AppName }
                        else { $MAMApp.mobileAppIdentifier.packageId }

                    }

                    Write-Host
                    Write-Host "Configuration Settings:" -ForegroundColor Yellow
                    Write-Host "Targeted management type: $ManagementType"
                    Write-Host "Jailbroken/rooted devices blocked: $($AndroidManagedAppProtection.deviceComplianceRequired)"
                    Write-Host "Min OS version: $($AndroidManagedAppProtection.minimumRequiredOsVersion)"
                    Write-Host "Min patch version: $($AndroidManagedAppProtection.minimumRequiredPatchVersion)"
                    Write-Host "Allowed device manufacturer(s): $($AndroidManagedAppProtection.allowedAndroidDeviceManufacturers)"
                    write-host "Require managed browser: $($AndroidManagedAppProtection.managedBrowserToOpenLinksRequired)"
                    Write-Host "Contact sync blocked: $($AndroidManagedAppProtection.contactSyncBlocked)"
                    Write-Host "Printing blocked: $($AndroidManagedAppProtection.printblocked)"
                    Write-Host
                    write-host "-------------------------------------------------------------------"
                    write-host
                    
                    }
                
                }

            }
            
        }     

        # If iOS Managed App Policy
    
        elseif($ManagedAppPolicy.'@odata.type' -eq "#microsoft.graph.iosManagedAppProtection"){
    
            $iOSManagedAppProtection = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "iOS"

            $MAMApps = $iOSManagedAppProtection.apps
    
            $iOSAssignments = ($iOSManagedAppProtection | select assignments).assignments
    
            if($iOSAssignments){
    
                foreach($Group in $iOSAssignments.target){
    
                    if($AADGroups.id -contains $Group.groupId){

                    $AssignmentCount++

                    $GroupID = $Group.GroupId
                    $GroupTargetType = $Group.'@odata.type'.split(".")[-1]

                    $targetedAppManagementLevels = $iOSManagedAppProtection.targetedAppManagementLevels

                        switch ($targetedAppManagementLevels){

                            "unspecified" {$ManagementType = "All app types";break}
                            "mdm" {$ManagementType = "Apps on managed devices";break}
                            "unmanaged" {$ManagementType = "Apps on unmanaged devices";break}

                            }

                    write-host "Policy name: " -NoNewline
                    write-host $iOSManagedAppProtection.displayname -ForegroundColor Green
                    write-host "Group assigned: " -NoNewline
                    write-host (get-aadgroup -id $GroupID).displayname

                    if($GroupTargetType -eq "exclusionGroupAssignmentTarget"){
                    
                        Write-Host "Group Target: " -NoNewline
                        Write-Host "Excluded" -ForegroundColor Red
                    
                    }

                    elseif($GroupTargetType -eq "GroupAssignmentTarget"){
                    
                        Write-Host "Group Target: " -NoNewline
                        Write-Host "Included" -ForegroundColor Green
                    
                    }

                    Write-Host
                    Write-Host "Targeted Apps:" -ForegroundColor Yellow

                    foreach($MAMApp in $MAMApps){

                        $AppName = (Get-IntuneMAMApplication -bundleid $MAMApp.mobileAppIdentifier.bundleId).displayName

                        if($AppName){ $AppName }
                        else { $MAMApp.mobileAppIdentifier.bundleId }

                    }

                    Write-Host
                    Write-Host "Configuration Settings:" -ForegroundColor Yellow
                    Write-Host "Targeted management type: $ManagementType"
                    Write-Host "Jailbroken/rooted devices blocked: $($iOSManagedAppProtection.deviceComplianceRequired)"
                    Write-Host "Min OS version: $($iOSManagedAppProtection.minimumRequiredOsVersion)"
                    Write-Host "Allowed device model(s): $($iOSManagedAppProtection.allowedIosDeviceModels)"
                    write-host "Require managed browser: $($iOSManagedAppProtection.managedBrowserToOpenLinksRequired)"
                    Write-Host "Contact sync blocked: $($iOSManagedAppProtection.contactSyncBlocked)"
                    Write-Host "FaceId blocked: $($iOSManagedAppProtection.faceIdBlocked)"
                    Write-Host "Printing blocked: $($iOSManagedAppProtection.printblocked)"
                    Write-Host
                    write-host "-------------------------------------------------------------------"
                    write-host

                    }

                }

            }
    
        }

    }

    if($AssignmentCount -eq 0){

        Write-Host "No $OS App Protection Policies Assigned..."
        Write-Host
        write-host "-------------------------------------------------------------------"
        write-host

    }

}

else {

    Write-Host "No $OS App Protection Policies Exist..."
    Write-Host
    write-host "-------------------------------------------------------------------"
    write-host

}

#endregion

####################################################

#region App Configuration Policies: Managed Apps

Write-Host "App Configuration Policies: Managed Apps" -ForegroundColor Cyan
Write-Host
write-host "-------------------------------------------------------------------"
Write-Host

$TargetedManagedAppConfigurations = Get-TargetedManagedAppConfigurations

$TMACAssignmentCount = 0

if($TargetedManagedAppConfigurations){

$TMACCount = @($TargetedManagedAppConfigurations).count

    foreach($TargetedManagedAppConfiguration in $TargetedManagedAppConfigurations){

    $PolicyId = $TargetedManagedAppConfiguration.id

    $ManagedAppConfiguration = Get-TargetedManagedAppConfigurations -PolicyId $PolicyId

    $MAMApps = $ManagedAppConfiguration.apps

        if($ManagedAppConfiguration.assignments){

            foreach($group in $ManagedAppConfiguration.assignments){

                if($AADGroups.id -contains $Group.target.GroupId){

                $TMACAssignmentCount++

                $GroupID = $Group.target.GroupId
                $GroupTargetType = $Group.target.'@odata.type'.split(".")[-1]

                write-host "Policy name: " -NoNewline
                write-host $ManagedAppConfiguration.displayname -ForegroundColor Green
                write-host "Group assigned: " -NoNewline
                write-host (get-aadgroup -id $GroupID).displayname

                if($GroupTargetType -eq "exclusionGroupAssignmentTarget"){
                    
                    Write-Host "Group Target: " -NoNewline
                    Write-Host "Excluded" -ForegroundColor Red
                    
                }

                elseif($GroupTargetType -eq "GroupAssignmentTarget"){
                    
                    Write-Host "Group Target: " -NoNewline
                    Write-Host "Included" -ForegroundColor Green
                    
                }

                Write-Host
                Write-Host "Targeted Apps:" -ForegroundColor Yellow

                foreach($MAMApp in $MAMApps){

                    if($MAMApp.mobileAppIdentifier.'@odata.type' -eq "#microsoft.graph.androidMobileAppIdentifier"){
                    
                        $AppName = (Get-IntuneMAMApplication -packageId $MAMApp.mobileAppIdentifier.packageId)
                        
                        if($AppName.'@odata.type' -like "*$OS*"){

                            Write-Host $AppName.displayName "-" $AppName.'@odata.type' -ForegroundColor Green
                        
                        }
                        
                        else {
                        
                            Write-Host $AppName.displayName "-" $AppName.'@odata.type'
                        
                        }

                    }
                    
                    elseif($MAMApp.mobileAppIdentifier.'@odata.type' -eq "#microsoft.graph.iosMobileAppIdentifier"){
                    
                        $AppName = (Get-IntuneMAMApplication -bundleId $MAMApp.mobileAppIdentifier.bundleId)
                        
                        if($AppName.'@odata.type' -like "*$OS*"){

                            Write-Host $AppName.displayName "-" $AppName.'@odata.type' -ForegroundColor Green
                        
                        }
                        
                        else {
                        
                            Write-Host $AppName.displayName "-" $AppName.'@odata.type'
                        
                        }
                    
                    }

                }

                Write-Host
                Write-Host "Configuration Settings:" -ForegroundColor yellow

                $ExcludeGroup = $Group.target.'@odata.type'
                
                $AppConfigNames = $ManagedAppConfiguration.customsettings

                    foreach($Config in $AppConfigNames){

                        $searchName = $config.name

                        if ($Config.name -like "*.*") {
                            
                        $Name = ($config.name).split(".")[-1]
                        

                        }

                        elseif ($Config.name -like "*_*"){
                            
                        $_appConfigName = ($config.name).replace("_"," ")
                        $Name = (Get-Culture).TextInfo.ToTitleCase($_appConfigName.tolower())

                        }

                        else {
                            
                        $Name = $config.name
                                                       
                        }

                        $Value = ($TargetedManagedAppConfiguration.customSettings | ? { $_.Name -eq "$searchName" } | select value).value

                        if ($name -like "*ListURLs*"){
                                
                            $value = $Value.replace("|",", ")

                            Write-Host
                            Write-Host "$($Name):" -ForegroundColor Yellow
                            Write-Host $($Value)
                                
                        }

                        else {
                                
                        Write-Host "$($Name): $($Value)"
                                
                        }

                    }

                Write-Host
                write-host "-------------------------------------------------------------------"
                write-host

                }   

            }

        }

    }

    if($TMACAssignmentCount -eq 0){

        Write-Host "No $OS App Configuration Policies: Managed Apps Assigned..."
        Write-Host
        write-host "-------------------------------------------------------------------"
        write-host

    }

}

else {

    Write-Host "No $OS App Configuration Policies: Managed Apps Exist..."
    Write-Host
    write-host "-------------------------------------------------------------------"
    write-host

}

#endregion

####################################################

#region App Configuration Policies: Managed Devices

Write-Host "App Configuration Policies: Managed Devices" -ForegroundColor Cyan
Write-Host
write-host "-------------------------------------------------------------------"
Write-Host

$AppConfigurations = Get-MobileAppConfigurations | ? { $_.'@odata.type' -like "*$OS*" }

$MACAssignmentCount = 0

if($AppConfigurations){

    foreach($AppConfiguration in $AppConfigurations){

        if($AppConfiguration.assignments){

            foreach($group in $AppConfiguration.assignments){

                if($AADGroups.id -contains $Group.target.GroupId){

                $MACAssignmentCount++

                $GroupID = $Group.target.GroupId
                $GroupTargetType = $Group.target.'@odata.type'.split(".")[-1]

                write-host "Policy name: " -NoNewline
                write-host $AppConfiguration.displayname -ForegroundColor Green
                write-host "Group assigned: " -NoNewline
                write-host (get-aadgroup -id $GroupID).displayname

                if($GroupTargetType -eq "exclusionGroupAssignmentTarget"){
                    
                    Write-Host "Group Target: " -NoNewline
                    Write-Host "Excluded" -ForegroundColor Red
                    
                }

                elseif($GroupTargetType -eq "GroupAssignmentTarget"){
                    
                    Write-Host "Group Target: " -NoNewline
                    Write-Host "Included" -ForegroundColor Green
                    
                }

                $TargetedApp = Get-IntuneApplication -id $AppConfiguration.targetedMobileApps
                Write-Host
                Write-Host "Targeted Mobile App:" -ForegroundColor Yellow
                Write-Host $TargetedApp.displayName "-" $TargetedApp.'@odata.type'
                Write-Host
                Write-Host "Configuration Settings:" -ForegroundColor yellow

                $ExcludeGroup = $Group.target.'@odata.type'

                $Type = ($AppConfiguration.'@odata.type'.split(".")[2] -creplace '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim()

                if($AppConfiguration.settings){

                    $AppConfigNames = $AppConfiguration.settings

                    foreach($Config in $AppConfigNames){

                        if ($Config.appConfigKey -like "*.*") {
                            
                            if($config.appConfigKey -like "*userChangeAllowed*"){
                        
                            $appConfigKey = ($config.appConfigKey).split(".")[-2,-1]
                            $appConfigKey = $($appConfigKey)[-2] + " - " + $($appConfigKey)[-1]
                            
                            }

                            else {
                        
                            $appConfigKey = ($config.appConfigKey).split(".")[-1]
                        
                            }

                        }

                        elseif ($Config.appConfigKey -like "*_*"){
                            
                        $appConfigKey = ($config.appConfigKey).replace("_"," ")

                        }
 
                        else {
                        
                        $appConfigKey = ($config.appConfigKey)
                        
                        }

                        Write-Host "$($appConfigKey): $($config.appConfigKeyValue)"

                    }

                }

                elseif($AppConfiguration.payloadJson){

                    $JSON = $AppConfiguration.payloadJson

                    $Configs = ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("$JSON")) | ConvertFrom-Json | select managedproperty).managedproperty

                    foreach($Config in $Configs){

                        if ($Config.key -like "*.*") {
                            
                        $appConfigKey = ($config.key).split(".")[-1]
                            
                        }

                        elseif ($Config.key -like "*_*"){
                            
                        $_appConfigKey = ($config.key).replace("_"," ")
                        $appConfigKey = (Get-Culture).TextInfo.ToTitleCase($_appConfigKey.tolower())

                        }

                        Write-Host "$($appConfigKey): $($Config.valueString)$($Config.valueBool)"

                    }

                }

                Write-Host
                write-host "-------------------------------------------------------------------"
                write-host

                }

            }            
     
       }

    }

    if($MACAssignmentCount -eq 0){

        Write-Host "No $OS App Configuration Policies: Managed Devices Assigned..."
        Write-Host
        write-host "-------------------------------------------------------------------"
        write-host

    }

}

else {

    Write-Host "No $OS App Configuration Policies: Managed Devices Exist..." 
    Write-Host

}

#endregion

####################################################

Write-Host "Evaluation complete..." -ForegroundColor Green
Write-Host
write-host "-------------------------------------------------------------------"
Write-Host
