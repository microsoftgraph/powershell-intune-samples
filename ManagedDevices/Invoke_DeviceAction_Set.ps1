
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
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

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

Function Invoke-DeviceAction(){

<#
.SYNOPSIS
This function is used to set a generic intune resources from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets a generic Intune Resource
.EXAMPLE
Invoke-DeviceAction -DeviceID $DeviceID -remoteLock
Resets a managed device passcode
.NOTES
NAME: Invoke-DeviceAction
#>

[cmdletbinding()]

param
(
    [switch]$RemoteLock,
    [switch]$ResetPasscode,
    [switch]$Wipe,
    [switch]$Retire,
    [switch]$Delete,
    [switch]$Sync,
    [switch]$Rename,
    [Parameter(Mandatory=$true,HelpMessage="DeviceId (guid) for the Device you want to take action on must be specified:")]
    $DeviceID
)

$graphApiVersion = "Beta"

    try {

        $Count_Params = 0

        if($RemoteLock.IsPresent){ $Count_Params++ }
        if($ResetPasscode.IsPresent){ $Count_Params++ }
        if($Wipe.IsPresent){ $Count_Params++ }
        if($Retire.IsPresent){ $Count_Params++ }
        if($Delete.IsPresent){ $Count_Params++ }
        if($Sync.IsPresent){ $Count_Params++ }
        if($Rename.IsPresent){ $Count_Params++ }

        if($Count_Params -eq 0){

        write-host "No parameter set, specify -RemoteLock -ResetPasscode -Wipe -Delete -Sync or -rename against the function" -f Red

        }

        elseif($Count_Params -gt 1){

        write-host "Multiple parameters set, specify a single parameter -RemoteLock -ResetPasscode -Wipe -Delete or -Sync against the function" -f Red

        }

        elseif($RemoteLock){

        $Resource = "deviceManagement/managedDevices/$DeviceID/remoteLock"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
        write-verbose $uri
        Write-Verbose "Sending remoteLock command to $DeviceID"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

        }

        elseif($ResetPasscode){

            write-host
            write-host "Are you sure you want to reset the Passcode this device? Y or N?"
            $Confirm = read-host

            if($Confirm -eq "y" -or $Confirm -eq "Y"){

            $Resource = "deviceManagement/managedDevices/$DeviceID/resetPasscode"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending remotePasscode command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

            }

            else {

            Write-Host "Reset of the Passcode for the device $DeviceID was cancelled..."

            }

        }

        elseif($Wipe){

        write-host
        write-host "Are you sure you want to wipe this device? Y or N?"
        $Confirm = read-host

            if($Confirm -eq "y" -or $Confirm -eq "Y"){

            $Resource = "deviceManagement/managedDevices/$DeviceID/wipe"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending wipe command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

            }

            else {

            Write-Host "Wipe of the device $DeviceID was cancelled..."

            }

        }

        elseif($Retire){

        write-host
        write-host "Are you sure you want to retire this device? Y or N?"
        $Confirm = read-host

            if($Confirm -eq "y" -or $Confirm -eq "Y"){

            $Resource = "deviceManagement/managedDevices/$DeviceID/retire"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending retire command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

            }

            else {

            Write-Host "Retire of the device $DeviceID was cancelled..."

            }

        }

        elseif($Delete){

        write-host
        Write-Warning "A deletion of a device will only work if the device has already had a retire or wipe request sent to the device..."
        Write-Host
        write-host "Are you sure you want to delete this device? Y or N?"
        $Confirm = read-host

            if($Confirm -eq "y" -or $Confirm -eq "Y"){

            $Resource = "deviceManagement/managedDevices('$DeviceID')"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending delete command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete

            }

            else {

            Write-Host "Deletion of the device $DeviceID was cancelled..."

            }

        }
        
        elseif($Sync){

        write-host
        write-host "Are you sure you want to sync this device? Y or N?"
        $Confirm = read-host

            if($Confirm -eq "y" -or $Confirm -eq "Y"){

            $Resource = "deviceManagement/managedDevices('$DeviceID')/syncDevice"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending sync command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post

            }

            else {

            Write-Host "Sync of the device $DeviceID was cancelled..."

            }

        }

        elseif($Rename){

        write-host "Please type the new device name:" -ForegroundColor Yellow
        $NewDeviceName = Read-Host

$JSON = @"

{
    deviceName:"$($NewDeviceName)"
}

"@

        write-host
        write-host "Note: The RenameDevice remote action is only supported on supervised iOS and Windows 10 Azure AD joined devices"
        write-host "Are you sure you want to rename this device to" $($NewDeviceName) "(Y or N?)"
        $Confirm = read-host

            if($Confirm -eq "y" -or $Confirm -eq "Y"){

            $Resource = "deviceManagement/managedDevices('$DeviceID')/setDeviceName"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending rename command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $Json -ContentType "application/json"

            }

            else {

            Write-Host "Rename of the device $DeviceID was cancelled..."

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

write-host
write-host "User Principal Name:" -f Yellow
$UPN = Read-Host

write-host

$User = Get-AADUser -userPrincipalName $UPN

$id = $User.Id
write-host "User ID:"$id

####################################################
# Get Users Devices
####################################################

Write-Host
Write-Host "Checking if the user" $User.displayName "has any devices assigned..." -ForegroundColor DarkCyan

$Devices = Get-AADUserDevices -UserID $id

####################################################
# Invoke-DeviceAction
####################################################

if($Devices){

$DeviceCount = @($Devices).count

Write-Host
Write-Host "User has $DeviceCount devices added to Intune..."
Write-Host

    if($Devices.id.count -gt 1){

    $Managed_Devices = $Devices.deviceName | sort -Unique

    $menu = @{}

    for ($i=1;$i -le $Managed_Devices.count; $i++) 
    { Write-Host "$i. $($Managed_Devices[$i-1])" 
    $menu.Add($i,($Managed_Devices[$i-1]))}

    Write-Host
    [int]$ans = Read-Host 'Enter Device id (Numerical value)'
    $selection = $menu.Item($ans)

        if($selection){

        $SelectedDevice = $Devices | ? { $_.deviceName -eq "$Selection" }

        $SelectedDeviceId = $SelectedDevice | select -ExpandProperty id

        write-host "User" $User.userPrincipalName "has device" $SelectedDevice.deviceName
        #Invoke-DeviceAction -DeviceID $SelectedDeviceId -RemoteLock -Verbose
        #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Retire -Verbose
        #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Wipe -Verbose
        #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Delete -Verbose
        #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Sync -Verbose
        #Invoke-DeviceAction -DeviceID $SelectedDeviceId -Rename -Verbose

        }

    }

    elseif($Devices.id.count -eq 1){

        write-host "User" $User.userPrincipalName "has one device" $Devices.deviceName
        #Invoke-DeviceAction -DeviceID $Devices.id -RemoteLock -Verbose
        #Invoke-DeviceAction -DeviceID $Devices.id -Retire -Verbose
        #Invoke-DeviceAction -DeviceID $Devices.id -Wipe -Verbose
        #Invoke-DeviceAction -DeviceID $Devices.id -Delete -Verbose
        #Invoke-DeviceAction -DeviceID $Devices.id -Sync -Verbose
        #Invoke-DeviceAction -DeviceID $Devices.id -Rename -Verbose

    }

}

else {

Write-Host
write-host "User $UPN doesn't have any owned Devices..." -f Yellow

}

write-host



