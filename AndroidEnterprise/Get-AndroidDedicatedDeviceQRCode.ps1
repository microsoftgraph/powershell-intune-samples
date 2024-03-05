
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

Function Get-AndroidEnrollmentProfile {

<#
.SYNOPSIS
Gets Android Enterprise Enrollment Profile
.DESCRIPTION
Gets Android Enterprise Enrollment Profile
.EXAMPLE
Get-AndroidEnrollmentProfile
.NOTES
NAME: Get-AndroidEnrollmentProfile
#>

$graphApiVersion = "Beta"
$Resource = "deviceManagement/androidDeviceOwnerEnrollmentProfiles"
    
    try {
        
        $now = (Get-Date -Format s)    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=tokenExpirationDateTime gt $($now)z"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).value
    
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

Function Get-AndroidQRCode{

<#
.SYNOPSIS
Gets Android Device Owner Enrollment Profile QRCode Image
.DESCRIPTION
Gets Android Device Owner Enrollment Profile QRCode Image
.EXAMPLE
Get-AndroidQRCode
.NOTES
NAME: Get-AndroidQRCode
#>

[cmdletbinding()]

Param(
[parameter(Mandatory=$true)]
[string]$Profileid
)

$graphApiVersion = "Beta"

    try {
            
        $Resource = "deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($Profileid)?`$select=qrCodeImage"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get)
                    
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

$parent = [System.IO.Path]::GetTempPath()
[string] $name = [System.Guid]::NewGuid()
New-Item -ItemType Directory -Path (Join-Path $parent $name) | Out-Null
$TempDirPath = "$parent$name"

####################################################

$Profiles = Get-AndroidEnrollmentProfile

if($profiles){

$profilecount = @($profiles).count

    if(@($profiles).count -gt 1){

    Write-Host "Corporate-owned dedicated device profiles found: $profilecount"
    Write-Host

    $COSUprofiles = $profiles.Displayname | Sort-Object -Unique

    $menu = @{}

    for ($i=1;$i -le $COSUprofiles.count; $i++) 
    { Write-Host "$i. $($COSUprofiles[$i-1])" 
    $menu.Add($i,($COSUprofiles[$i-1]))}

    Write-Host
    $ans = Read-Host 'Choose a profile (numerical value)'

    if($ans -eq "" -or $ans -eq $null){

        Write-Host "Corporate-owned dedicated device profile can't be null, please specify a valid Profile..." -ForegroundColor Red
        Write-Host
        break

    }

    elseif(($ans -match "^[\d\.]+$") -eq $true){

    $selection = $menu.Item([int]$ans)

    Write-Host

        if($selection){

            $SelectedProfile = $profiles | ? { $_.DisplayName -eq "$Selection" }

            $SelectedProfileID = $SelectedProfile | select -ExpandProperty id

            $ProfileID = $SelectedProfileID

            $ProfileDisplayName = $SelectedProfile.displayName

        }

        else {

            Write-Host "Corporate-owned dedicated device profile selection invalid, please specify a valid Profile..." -ForegroundColor Red
            Write-Host
            break

        }

    }

    else {

        Write-Host "Corporate-owned dedicated device profile selection invalid, please specify a valid Profile..." -ForegroundColor Red
        Write-Host
        break

    }

}

    elseif(@($profiles).count -eq 1){

        $Profileid = (Get-AndroidEnrollmentProfile).id
        $ProfileDisplayName = (Get-AndroidEnrollmentProfile).displayname
    
        Write-Host "Found a Corporate-owned dedicated devices profile '$ProfileDisplayName'..."
        Write-Host

    }

    else {

        Write-Host
        write-host "No enrollment profiles found!" -f Yellow
        break

    }

Write-Warning "You are about to export the QR code for the Dedicated Device Enrollment Profile '$ProfileDisplayName'"
Write-Warning "Anyone with this QR code can Enrol a device into your tenant. Please ensure it is kept secure."
Write-Warning "If you accidentally share the QR code, you can immediately expire it in the Intune UI."
write-warning "Devices already enrolled will be unaffected."
Write-Host
Write-Host "Show token? [Y]es, [N]o"

$FinalConfirmation = Read-Host

    if ($FinalConfirmation -ne "y"){
    
        Write-Host "Exiting..."
        Write-Host
        break

    }

    else {

    Write-Host

    $QR = (Get-AndroidQRCode -Profileid $ProfileID)
    
    $QRType = $QR.qrCodeImage.type
    $QRValue = $QR.qrCodeImage.value
 
    $imageType = $QRType.split("/")[1]
 
    $filename = "$TempDirPath\$ProfileDisplayName.$imageType"

    $bytes = [Convert]::FromBase64String($QRValue)
    [IO.File]::WriteAllBytes($filename, $bytes)

        if (Test-Path $filename){

            Write-Host "Success: " -NoNewline -ForegroundColor Green
            write-host "QR code exported to " -NoNewline
            Write-Host "$filename" -ForegroundColor Yellow
            Write-Host

        }

        else {
        
            write-host "Oops! Something went wrong!" -ForegroundColor Red
        
        }
       
    }

}

else {

    Write-Host "No Corporate-owned dedicated device Profiles found..." -ForegroundColor Yellow
    Write-Host

}
