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
    $User,
    $Password
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

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always"

    if ($Password -eq $null) {
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters).Result
    }
    else {
        $userCred = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential" -ArgumentList $User, $Password
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $userCred).Result
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

Function Assign-ProfileToDevices(){
<#
.SYNOPSIS
This function is used to assign a profile to given devices using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and assigns a profile to given devices
.EXAMPLE
Assign-ProfileToDevices
Assigns a profile to given devices in Intune
.NOTES
NAME: Assign-ProfileToDevices
#>

[cmdletbinding()]

param
(
    $Devices,
    $ProfileId
)

$graphApiVersion = "Beta"
$ResourceSegment = "deviceManagement/enrollmentProfiles('{0}')/updateDeviceProfileAssignment"

    try {

        if([string]::IsNullOrWhiteSpace($ProfileId)){

        $ProfileId = Read-Host -Prompt "Please specify profile Id to assign to devices"
        Write-Host

        }

        $id = [Guid]::NewGuid();
        if([string]::IsNullOrWhiteSpace($ProfileId) -or ![Guid]::TryParse($ProfileId, [ref]$id)){

            write-host "Invalid ProfileId specified, please specify valid ProfileId to assign to devices..." -f Red

        }
        elseif ($Devices -eq $null -or $Devices.Count -eq 0){
            
            write-host "No devices specified, please specify a list of devices to assign..." -f Red
        }
        else {

            $Resource = "deviceManagement/enrollmentProfiles('$ProfileId')/updateDeviceProfileAssignment"

            $JSON = @{ "deviceIds" = $Devices } | ConvertTo-Json

            Test-JSON -JSON $JSON

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
            
            Write-Host "Devices assigned!" -f Green
        }

    }

    catch {

    Write-Host
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

Function Get-UnAssignedDevices(){

<#
.SYNOPSIS
This function is used to get all un-assigned bulk devices using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all un-assigned bulk devices
.EXAMPLE
Get-UnAssignedDevices
Gets all un-assigned bulk devices
.NOTES
NAME: Get-UnAssignedDevices
#>

[cmdletbinding()]

param
(
)

$graphApiVersion = "Beta"
$ResourceSegment = "deviceManagement/importedAppleDeviceIdentities?`$filter=discoverySource eq 'deviceEnrollmentProgram'"

    try {

        [System.String]$devicesNextLink = ''
        [System.String[]]$unAssignedDevices = @()
        [System.Uri]$uri = "https://graph.microsoft.com/$graphApiVersion/$($ResourceSegment)"

        DO
        {
            $response = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get -ContentType "application/json"
            $devicesNextLink = $response."@odata.nextLink"
            $uri = $devicesNextLink

            foreach($device in $response)
            {
                if ([string]::IsNullOrEmpty($device.Value.RequestedEnrollmentProfileId)) 
                {
                    $unAssignedDevices += $device.Value.SerialNumber
                }

                if ($unAssignedDevices.Count -ge 1000) 
                { 
                   $devicesNextLink = ''
                   break
                }
            }
        }While(![string]::IsNullOrEmpty($devicesNextLink))   

        Write-Host $unAssignedDevices -f Yellow

        return $unAssignedDevices
    }

    catch {

    Write-Host
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

$global:devices = Get-UnAssignedDevices
$global:profileId = ''

Assign-ProfileToDevices -Devices $global:devices -ProfileId $profileId