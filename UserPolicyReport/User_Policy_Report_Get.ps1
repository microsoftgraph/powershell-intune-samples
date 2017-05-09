
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
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value

        }

        else {

            if($Property -eq "" -or $Property -eq $null){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName"
            Write-Verbose $uri
            Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get

            }

            else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName/$Property"
            Write-Verbose $uri
            (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value

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

Function Get-AADUserDevices(){

<#
.SYNOPSIS
This function is used to get an AAD User Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a users devices registered with Intune MDM
.EXAMPLE
Get-AADUserDevices -UserID $UserID
Returns all user devices registered in Intune MDM
.NOTES
NAME: Get-AADUserDevices
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true,HelpMessage="UserID (guid) for the user you want to take action on must be specified:")]
    $UserID
)

# Defining Variables
$graphApiVersion = "beta"
$Resource = "users/$UserID/managedDevices"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Write-Verbose $uri
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

Function Get-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to get device compliance policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device compliance policies
.EXAMPLE
Get-DeviceCompliancePolicy
Returns any device compliance policies configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -Android
Returns any device compliance policies for Android configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -iOS
Returns any device compliance policies for iOS configured in Intune
.NOTES
NAME: Get-DeviceCompliancePolicy
#>

[cmdletbinding()]

param
(
    $Name,
    [switch]$Android,
    [switch]$iOS,
    [switch]$Win10
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/deviceCompliancePolicies"

    try {

        $Count_Params = 0

        if($Android.IsPresent){ $Count_Params++ }
        if($iOS.IsPresent){ $Count_Params++ }
        if($Win10.IsPresent){ $Count_Params++ }
        if($Name.IsPresent){ $Count_Params++ }

        if($Count_Params -gt 1){

        write-host "Multiple parameters set, specify a single parameter -Android -iOS or -Win10 against the function" -f Red

        }

        elseif($Android){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value | Where-Object { ($_.'@odata.type').contains("android") }

        }

        elseif($iOS){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value | Where-Object { ($_.'@odata.type').contains("ios") }

        }

        elseif($Win10){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value | Where-Object { ($_.'@odata.type').contains("windows10CompliancePolicy") }

        }

        elseif($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value

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

Function Get-DeviceCompliancePolicyAssignment(){

<#
.SYNOPSIS
This function is used to get device compliance policy assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a device compliance policy assignment
.EXAMPLE
Get-DeviceCompliancePolicyAssignment -id guid
Returns any device compliance policy assignment configured in Intune
.NOTES
NAME: Get-DeviceCompliancePolicyAssignment
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Device Compliance Policy you want to check assignment")]
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceCompliancePolicies"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/groupAssignments"
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

Function Get-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to get device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device configuration policies
.EXAMPLE
Get-DeviceConfigurationPolicy
Returns any device configuration policies configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    $name
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"

    try {

        if($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value

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

Function Get-DeviceConfigurationPolicyAssignment(){

<#
.SYNOPSIS
This function is used to get device configuration policy assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a device configuration policy assignment
.EXAMPLE
Get-DeviceConfigurationPolicyAssignment $id guid
Returns any device configuration policy assignment configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicyAssignment
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Device Configuration Policy you want to check assignment")]
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/groupAssignments"
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

write-host
write-host "User Principal Name:" -f Yellow
$UPN = Read-Host

$User = Get-AADUser -userPrincipalName $UPN

$UserID = $User.id

write-host
write-host "Display Name:"$User.displayName
write-host "User ID:"$User.id
write-host "User Principal Name:"$User.userPrincipalName
write-host

####################################################

$UserDevices = Get-AADUserDevices -UserID $UserID

    if($UserDevices){

        write-host "User Devices:" -f Yellow

        foreach($UserDevice in $UserDevices){

        write-host "Device Name:" $UserDevice.deviceName -f Cyan
        write-host "Owner Type:" $UserDevice.ownerType
        write-host "Last Sync Date:" $UserDevice.lastSyncDateTime
        write-host "OS:" $UserDevice.operatingSystem
        write-host "OS Version:" $UserDevice.osVersion
        write-host "EAS Activated:" $UserDevice.easActivated
        write-host "AAD Registered:" $UserDevice.aadRegistered
        write-host "Enrollment Type:" $UserDevice.enrollmentType
        write-host "Management State:" $UserDevice.managementState

            if($UserDevice.complianceState -ne "compliant"){
            write-host "Compliance State:" $UserDevice.complianceState -f Red
            }
            else {
            write-host "Compliance State:" $UserDevice.complianceState -f Green
            }

        write-host

        }

    }

    else {

    write-host "User Devices:" -f Yellow
    write-host "User has no devices"
    write-host

    }

####################################################

$MemberOf = Get-AADUser -userPrincipalName $UPN -Property MemberOf

$DirectoryRole = $MemberOf | ? { $_.'@odata.type' -eq "#microsoft.graph.directoryRole" }

    if($DirectoryRole){

    write-host "Directory Role:" -f Yellow
    $DirectoryRole.displayName
    write-host

    }

####################################################

$AssignedLicenses = Get-AADUser -userPrincipalName $UPN -Property assignedLicenses

    if($AssignedLicenses){

    write-host "User Assigned Skus:" -f Yellow

        foreach($license in $AssignedLicenses.skuId){
        $license
        }

    Write-Host

    }

####################################################

$AADGroups = $MemberOf | ? { $_.'@odata.type' -eq "#microsoft.graph.group" }

    if($AADGroups){

    write-host "AAD Group Membership:" -f Yellow

        foreach($AADGroup in $AADGroups){

        (Get-AADGroup -id $AADGroup.id).displayName

        }

    write-host

    }

    else {

    write-host "AAD Group Membership:" -f Yellow
    write-host "No Group Membership in AAD Groups"
    Write-Host

    }

####################################################

$CPs = Get-DeviceCompliancePolicy

if($CPs){

    write-host "Device Compliance Policies:" -f Yellow
    $CP_Names = @()

    foreach($CP in $CPs){

    $id = $CP.id

    $DCPA = Get-DeviceCompliancePolicyAssignment -id $id

        if($DCPA){

            foreach($Com_Group in $DCPA){

                if($AADGroups.id -contains $Com_Group.targetGroupId){

                $CP_Names += $CP.displayName

                }

            }

        }

    }

    if($CP_Names -ne $null){

    $CP_Names

    }

    else {

    write-host "No Device Compliance Policies Assigned"

    }

}

else {

write-host "Device Compliance Policies:" -f Yellow
write-host "No Device Compliance Policies Assigned"

}

write-host

####################################################

$DCPs = Get-DeviceConfigurationPolicy

if($DCPs){

    write-host "Device Configuration Policies:" -f Yellow
    $DCP_Names = @()

    foreach($DCP in $DCPs){

    $id = $DCP.id

    $DDCPA = Get-DeviceConfigurationPolicyAssignment -id $id

        if($AADGroups.id -contains $DDCPA.targetGroupId){

        $DCP_Names += $DCP.displayName

        }

    }

    if($DCP_Names -ne $null){

    $DCP_Names

    }

    else {

    write-host "No Device Configuration Policies Assigned"

    }

}

else {

write-host "Device Configuration Policies:" -f Yellow
write-host "No Device Configuration Policies Assigned"

}

write-host
