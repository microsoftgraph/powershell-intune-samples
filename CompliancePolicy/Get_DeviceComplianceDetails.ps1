
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################
Function Convert-MultiValuedStringsToString {
<#
.SYNOPSIS
This function is used covert multivalue objects into strings
.DESCRIPTION
This function is used covert multivalue objects into strings separated by a special character 
.EXAMPLE
Convert-MultiValuedStringsToString
.NOTES
NAME: Convert-MultiValuedStringsToString
#>
    param
   (
       [Parameter(Mandatory = $false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelinebyPropertyName=$false,
                   ValueFromRemainingArguments=$false,
                   Position=0
       )]
       [ValidateNotNullOrEmpty()]
       [String] $Seperator = "`n",
       [Parameter(Mandatory = $true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelinebyPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=1
       )]
       [ValidateNotNullOrEmpty()]
       [object] $object #Message,
   )
   Process {
       $results= $object |
       ForEach-Object {
           $properties = New-Object PSObject    
           $_.PSObject.Properties | 
               ForEach-Object {
                   $propertyName = $_.Name
                   $propertyValue = $_.Value
                   If ($propertyValue -NE $NULL) { 
                       $values = @()
                       ForEach ($value In $propertyValue) {
                           $values += $value.ToString()
                       }
                       Add-Member -inputObject $properties NoteProperty -name $propertyName -value $([String]::Join($Seperator,$values));
                       #@{Name=�BlockedRecipients�;Expression={[string]::join(";", ($_.BlockedREcipients))}}
                   } Else { 
                       Add-Member -inputObject $properties NoteProperty -name $propertyName -value $NULL
                   }
               }
           $properties
       }
       return $results
   }
}


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
    }else{
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
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
        }else{
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
        }
    }catch {
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    }
}

Function Get-DeviceComplianceDetails(){
<#
.SYNOPSIS
This function is used to get an AAD User Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a users devices registered with Intune MDM
.EXAMPLE
Get-DeviceComplianceDetails
Returns all user devices registered in Intune MDM
.NOTES
NAME: Get-DeviceComplianceDetails
#>

[cmdletbinding()]

# Defining Variables
$graphApiVersion = "beta"
$Resource = "deviceManagement/managedDevices"
$filter = '$filter=(((managementAgent%20eq%20%27mdm%27)%20or%20(managementAgent%20eq%20%27googleCloudDevicePolicyController%27)%20or%20(managementAgent%20eq%20%27easMdm%27)%20or%20(managementAgent%20eq%20%27jamf%27)%20or%20(managementAgent%20eq%20%27configurationManagerClientMdm%27)%20or%20(managementAgent%20eq%20%27configurationManagerClientMdmEas%27)%20or%20(managementAgent%20eq%20%27microsoft365ManagedMdm%27)))'
$select ='$select=id,userId,deviceName,ownerType,managedDeviceOwnerType,managementState,enrolledDateTime,lastSyncDateTime,chassisType,operatingSystem,deviceType,complianceState,jailBroken,managementAgent,osVersion,easActivated,easDeviceId,easActivationDateTime,aadRegistered,azureADRegistered,deviceEnrollmentType,lostModeState,activationLockBypassCode,emailAddress,azureActiveDirectoryDeviceId,azureADDeviceId,deviceRegistrationState,deviceCategoryDisplayName,isSupervised,exchangeLastSuccessfulSyncDateTime,exchangeAccessState,exchangeAccessStateReason,remoteAssistanceSessionUrl,remoteAssistanceSessionErrorDetails,isEncrypted,userPrincipalName,model,manufacturer,imei,complianceGracePeriodExpirationDateTime,serialNumber,phoneNumber,androidSecurityPatchLevel,userDisplayName,configurationManagerClientEnabledFeatures,wiFiMacAddress,deviceHealthAttestationState,meid,totalStorageSpaceInBytes,freeStorageSpaceInBytes,managedDeviceName,partnerReportedThreatState,preferMdmOverGroupPolicyAppliedDateTime,autopilotEnrolled,requireUserEnrollmentApproval,managementCertificateExpirationDate,iccid,udid,roleScopeTagIds,configurationManagerClientHealthState,hardwareInformation,deviceActionResults,usersLoggedOn'
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?$filter&$select"
        Write-Verbose $uri
        $DeviceComplianceDetailsResponse = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        $DeviceComplianceDetails = $DeviceComplianceDetailsResponse.value
        $DeviceComplianceNextLink = $DeviceComplianceDetailsResponse."@odata.nextLink"
        while ($DeviceComplianceNextLink -ne $null){
            $DeviceComplianceDetailsResponse = (Invoke-RestMethod -Uri $DeviceComplianceNextLink -Headers $authToken -Method Get)
            $DeviceComplianceNextLink = $DeviceComplianceDetailsResponse."@odata.nextLink"
            $DeviceComplianceDetails += $DeviceComplianceDetailsResponse.value

        }
        $DeviceComplianceDetails | Convert-MultiValuedStringsToString
    }catch{
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

# Authentication doesn't exist, calling Get-AuthToken function
}else {
    if($User -eq $null -or $User -eq ""){
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    }
    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
}


$ExportPath = Read-Host -Prompt "Please specify a path to export Managed Compliance Information data to e.g. C:\IntuneOutput"
# If the directory path doesn't exist prompt user to create the directory
if(!(Test-Path "$ExportPath")){
    Write-Host
    Write-Host "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow
    $Confirm = read-host
        if($Confirm -eq "y" -or $Confirm -eq "Y"){
        new-item -ItemType Directory -Path "$ExportPath" | Out-Null
        Write-Host
        }else {
            Write-Host "Creation of directory path was cancelled..." -ForegroundColor Red
            Write-Host
            break
        }
    }
Write-Host

###### REGION Collect Report Data

$Date = get-date
$Output = "DeviceComplianceDetails_" + $Date.Day + "-" + $Date.Month + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute
$data = Get-DeviceComplianceDetails
$data = $data | select-object -property id,userId,deviceName,ownerType,managedDeviceOwnerType,managementState,enrolledDateTime,lastSyncDateTime,chassisType,operatingSystem,deviceType,complianceState,jailBroken,managementAgent,osVersion,easActivated,easDeviceId,easActivationDateTime,aadRegistered,azureADRegistered,deviceEnrollmentType,lostModeState,activationLockBypassCode,emailAddress,azureActiveDirectoryDeviceId,azureADDeviceId,deviceRegistrationState,deviceCategoryDisplayName,isSupervised,exchangeLastSuccessfulSyncDateTime,exchangeAccessState,exchangeAccessStateReason,remoteAssistanceSessionUrl,remoteAssistanceSessionErrorDetails,isEncrypted,userPrincipalName,model,manufacturer,imei,complianceGracePeriodExpirationDateTime,serialNumber,phoneNumber,androidSecurityPatchLevel,userDisplayName,configurationManagerClientEnabledFeatures,wiFiMacAddress,deviceHealthAttestationState,meid,totalStorageSpaceInBytes,freeStorageSpaceInBytes,managedDeviceName,@{N='deviceThreatLevel';E={$_.partnerReportedThreatState}},preferMdmOverGroupPolicyAppliedDateTime,autopilotEnrolled,requireUserEnrollmentApproval,managementCertificateExpirationDate,iccid,udid,roleScopeTagIds,configurationManagerClientHealthState,hardwareInformation,deviceActionResults,usersLoggedOn
$data | Export-Csv -NoTypeInformation -NoClobber -Path "$ExportPath\$Output.csv"
write-host "Device Compliace Details has been exported suscessfully to $ExportPath\$Output.csv" -ForegroundColor green

