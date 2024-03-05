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

Function Get-AADGroups(){

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
$graphApiVersion = "beta"
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
    [Parameter(HelpMessage = "Compliance Platform")]
    [ValidateSet("Android","iOS","Windows10","AndroidEnterprise","macOS")]
    $Platform

)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/deviceCompliancePolicies?`$expand=assignments"

    try {


        if($Platform -eq "Android"){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("android") }

        }

        elseif($Platform -eq "iOS"){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("ios") }

        }

        elseif($Platform -eq "Windows10"){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("windows10CompliancePolicy") }

        }

        elseif($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

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
$DCP_resource = "deviceManagement/deviceConfigurations?`$expand=assignments"

    try {

        if($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
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

Function Get-AdministrativeTemplates(){

<#
.SYNOPSIS
This function is used to get Administrative Templates from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Administrative Templates
.EXAMPLE
Get-AdministrativeTemplates
Returns any Administrative Templates configured in Intune
.NOTES
NAME: Get-AdministrativeTemplates
#>

[cmdletbinding()]

param
(
    $name
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/groupPolicyConfigurations?`$expand=assignments"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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

Function Get-AssignmentFilters(){

<#
.SYNOPSIS
This function is used to get assignment filters from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any assignment filters
.EXAMPLE
Get-AssignmentFilters
Returns any assignment filters configured in Intune
.NOTES
NAME: Get-AssignmentFilters
#>

[cmdletbinding()]

param
(
    $name
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/assignmentFilters"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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

Function Get-SettingsCatalogPolicy(){

<#
.SYNOPSIS
This function is used to get Settings Catalog policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Settings Catalog policies
.EXAMPLE
Get-SettingsCatalogPolicy
Returns any Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform windows10
Returns any Windows 10 Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform macOS
Returns any MacOS Settings Catalog policies configured in Intune
.NOTES
NAME: Get-SettingsCatalogPolicy
#>

[cmdletbinding()]

param
(
    [parameter(Mandatory=$false)]
    [ValidateSet("windows10","macOS")]
    [ValidateNotNullOrEmpty()]
    [string]$Platform,
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    $id
)

$graphApiVersion = "beta"

    if($Platform){
        
        $Resource = "deviceManagement/configurationPolicies?`$filter=platforms has '$Platform' and technologies has 'mdm'"

    }

    elseif($id){

        $Resource = "deviceManagement/configurationPolicies('$id')/assignments"

    }

    else {

        $Resource = "deviceManagement/configurationPolicies?`$filter=technologies has 'mdm'"

    }

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
    $Name
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps?`$expand=assignments"

    try {

        if($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") -and (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }

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

write-host "Filters Name:" -f Yellow
$FilterName = Read-Host

if($FilterName -eq $null -or $FilterName -eq ""){

    write-host "Filter Name is Null..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break

}

####################################################

$Filters = Get-AssignmentFilters

$Filter = $Filters | ? { $_.displayName -eq "$FilterName" }

if(!$Filter){

    Write-Host
    Write-Host "Filter with Name '$FilterName' doesn't exist..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break

}

if($Filter.count -gt 1){

    Write-Host
    Write-Host "There are multiple filters with the same display name '$FilterName', unique names should be used..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break

}

Write-Host
write-host "-------------------------------------------------------------------"
Write-Host
Write-Host "Filter found..." -f Green
Write-Host "Filter Id:       " $Filter.id
Write-Host "Filter Name:     " $Filter.displayName
Write-Host "Filter Platform: " $Filter.platform
Write-Host "Filter Rule:     " $filter.rule
Write-Host "Filter Scope Tag:" $filter.roleScopeTags
Write-Host

####################################################

$Activity = "Filter Usage Check"

####################################################

#region CompliancePolicies

$CPs = Get-DeviceCompliancePolicy

write-host "-------------------------------------------------------------------"
write-host "Device Compliance Policies" -f Cyan
write-host "-------------------------------------------------------------------"

if(@($CPs).count -ge 1){

    $CPCount = @($CPs).count
    $i = 1

    $CP_Count = 0

    foreach($CP in $CPs){

    $id = $CP.id

    $DCPA = $CP.assignments

        if($DCPA){

            foreach($Com_Group in $DCPA){

                if($Com_Group.target.deviceAndAppManagementAssignmentFilterId -eq $Filter.id){

                    Write-Host
                    Write-Host "Policy Name: " -NoNewline
                    Write-Host $CP.displayName -f green
                    Write-Host "Filter Type:" $Com_Group.target.deviceAndAppManagementAssignmentFilterType
                    
                    if($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget"){

                        Write-Host "AAD Group Name: All Devices"

                    }

                    elseif($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allLicensedUsersAssignmentTarget"){

                        Write-Host "AAD Group Name: All Users"

                    }

                    else {

                        Write-Host "AAD Group Name:" (Get-AADGroups -id $Com_Group.target.groupId).displayName

                    }

                    Write-Host
                    $CP_Count++

                }

            }

        }

        Write-Progress -Activity "$Activity" -status "Checking Device Compliance Policy $i of $CPCount" `
        -percentComplete ($i / $CPCount*100)
        $i++

    }

    Write-Progress -Completed -Activity "$Activity"

    if($CP_Count -eq 0){

        Write-Host
        Write-Host "Filter '$FilterName' not used..." -ForegroundColor Yellow
        Write-Host

    }

}

else {

Write-Host
write-host "No Device Compliance Policies Found..." -f Red
write-host

}

#endregion

####################################################

#region ConfigurationPolicies

$DCPs = Get-DeviceConfigurationPolicy

write-host "-------------------------------------------------------------------"
write-host "Device Configuration Policies" -f Cyan
write-host "-------------------------------------------------------------------"

if($DCPs){

    $DCPsCount = @($DCPs).count
    $i = 1
    
    $DCP_Count = 0

    foreach($DCP in $DCPs){

    $id = $DCP.id

    $CPA = $DCP.assignments

        if($CPA){

            foreach($Com_Group in $CPA){

                if($Com_Group.target.deviceAndAppManagementAssignmentFilterId -eq $Filter.id){

                    Write-Host
                    Write-Host "Policy Name: " -NoNewline
                    Write-Host $DCP.displayName -f green
                    Write-Host "Filter Type:" $Com_Group.target.deviceAndAppManagementAssignmentFilterType
                    
                    if($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget"){

                        Write-Host "AAD Group Name: All Devices"

                    }

                    elseif($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allLicensedUsersAssignmentTarget"){

                        Write-Host "AAD Group Name: All Users"

                    }

                    else {

                        Write-Host "AAD Group Name:" (Get-AADGroups -id $Com_Group.target.groupId).displayName

                    }

                    Write-Host
                    $DCP_Count++

                }
            

            }

        }

        Write-Progress -Activity "$Activity" -status "Checking Device Configuration Policy $i of $DCPsCount" `
        -percentComplete ($i / $DCPsCount*100)
        $i++

    }

    Write-Progress -Completed -Activity "$Activity"

    if($DCP_Count -eq 0){

        Write-Host
        Write-Host "Filter '$FilterName' not used..." -ForegroundColor Yellow
        Write-Host

    }

}

else {

    Write-Host
    write-host "No Device Configuration Policies Found..."
    Write-Host

}

#endregion

####################################################

#region SettingsCatalog

$SCPolicies = Get-SettingsCatalogPolicy

write-host "-------------------------------------------------------------------"
write-host "Settings Catalog Policies" -f Cyan
write-host "-------------------------------------------------------------------"

if($SCPolicies){

    $SCPCount = @($SCPolicies).count
    $i = 1

    $SC_Count = 0

    foreach($SCPolicy in $SCPolicies){

    $id = $SCPolicy.id

    $SCPolicyAssignment = Get-SettingsCatalogPolicy -id $id

        if($SCPolicyAssignment){

            foreach($Com_Group in $SCPolicyAssignment){
            
                if($Com_Group.target.deviceAndAppManagementAssignmentFilterId -eq $Filter.id){

                    Write-Host
                    Write-Host "Policy Name: " -NoNewline
                    Write-Host $SCPolicy.name -f green
                    Write-Host "Filter Type:" $Com_Group.target.deviceAndAppManagementAssignmentFilterType
                    
                    if($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget"){

                        Write-Host "AAD Group Name: All Devices"

                    }

                    elseif($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allLicensedUsersAssignmentTarget"){

                        Write-Host "AAD Group Name: All Users"

                    }

                    else {

                        Write-Host "AAD Group Name:" (Get-AADGroups -id $Com_Group.target.groupId).displayName

                    }

                    Write-Host
                    $SC_Count++

                }

            }

        }

        Write-Progress -Activity "$Activity" -status "Checking Settings Catalog $i of $SCPCount" `
        -percentComplete ($i / $SCPCount*100)
        $i++

    }

    Write-Progress -Completed -Activity "$Activity"

    if($SC_Count -eq 0){

        Write-Host
        Write-Host "Filter '$FilterName' not used..." -ForegroundColor Yellow
        Write-Host

    }

}

else {

    write-host
    write-host "No Settings Catalog Policies Found..."
    Write-Host

}

#endregion

####################################################

#region ADMX Templates

$ADMXPolicies = Get-AdministrativeTemplates

write-host "-------------------------------------------------------------------"
write-host "Administrative Templates Policies" -f Cyan
write-host "-------------------------------------------------------------------"

if($ADMXPolicies){

    $ATCount = @($ADMXPolicies).count
    $i = 1

    $AT_Count = 0

    foreach($ADMXPolicy in $ADMXPolicies){

    $id = $ADMXPolicy.id

    $ATPolicyAssignment = $ADMXPolicy.assignments

        if($ATPolicyAssignment){

            foreach($Com_Group in $ATPolicyAssignment){

                if($Com_Group.target.deviceAndAppManagementAssignmentFilterId -eq $Filter.id){

                    Write-Host
                    Write-Host "Policy Name: " -NoNewline
                    Write-Host $ADMXPolicy.displayName -f green
                    Write-Host "Filter Type:" $Com_Group.target.deviceAndAppManagementAssignmentFilterType
                    
                    if($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget"){

                        Write-Host "AAD Group Name: All Devices"

                    }

                    elseif($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allLicensedUsersAssignmentTarget"){

                        Write-Host "AAD Group Name: All Users"

                    }

                    else {

                        Write-Host "AAD Group Name:" (Get-AADGroups -id $Com_Group.target.groupId).displayName

                    }

                    Write-Host
                    $AT_Count++

                }

            }

        }

        Write-Progress -Activity "$Activity" -status "Checking Administrative Templates Policy $i of $ATCount" `
        -percentComplete ($i / $ATCount*100)
        $i++

    }

    Write-Progress -Completed -Activity "$Activity"

    if($AT_Count -eq 0){

        Write-Host
        Write-Host "Filter '$FilterName' not used..." -ForegroundColor Yellow
        Write-Host

    }

}

else {

Write-Host
write-host "No Administrative Templates Policies Found..."
Write-Host

}

#endregion

####################################################

#region IntuneApplications

$Apps = Get-IntuneApplication

write-host "-------------------------------------------------------------------"
write-host "Intune Applications" -f Cyan
write-host "-------------------------------------------------------------------"

if($Apps){

    $AppsCount = @($Apps).count
    $i = 1

    $App_Count = 0

    foreach($App in $Apps){

    $id = $App.id

    $AppAssignment = $app.assignments

        if($AppAssignment){

            foreach($Com_Group in $AppAssignment){
            
                if($Com_Group.target.deviceAndAppManagementAssignmentFilterId -eq $Filter.id){

                    Write-Host
                    Write-Host "Application Name: " -NoNewline
                    Write-Host $App.displayName -f green
                    Write-Host "Filter Type:" $Com_Group.target.deviceAndAppManagementAssignmentFilterType

                    if($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget"){

                        Write-Host "AAD Group Name: All Devices"

                    }

                    elseif($Com_Group.target.'@odata.type' -eq "#microsoft.graph.allLicensedUsersAssignmentTarget"){

                        Write-Host "AAD Group Name: All Users"

                    }

                    else {

                        Write-Host "AAD Group Name:" (Get-AADGroups -id $Com_Group.target.groupId).displayName

                    }

                    Write-Host
                    $App_Count++

                }

            }

        }

        Write-Progress -Activity "$Activity" -status "Checking Intune Application $i of $AppsCount" `
        -percentComplete ($i / $AppsCount*100)
        $i++

    }

    Write-Progress -Completed -Activity "$Activity"

    if($App_Count -eq 0){

        Write-Host
        Write-Host "Filter '$FilterName' not used..." -ForegroundColor Yellow
        Write-Host

    }

}

else {

write-host
write-host "No Intune Applications Found..."
Write-Host

}

#endregion

####################################################

write-host "-------------------------------------------------------------------"
Write-Host "Overall Analysis" -ForegroundColor Cyan
write-host "-------------------------------------------------------------------"
Write-Host "Status of each area of MEM that support Filters assignment status"
Write-Host
Write-Host "Applicable OS Type: " -NoNewline
Write-Host $Filter.Platform -ForegroundColor Yellow
Write-Host 
Write-Host "Compliance Policies:           " $CP_Count
write-host "Device Configuration Policies: " $DCP_Count
Write-Host "Settings Catalog Policies:     " $SC_Count
Write-Host "Administrative Templates:      " $AT_Count
Write-Host "Intune Applications:           " $App_Count
Write-Host

$CountFilters = $CP_Count + $DCP_Count + $SC_Count + $AT_Count + $App_Count

Write-Host "Total Filters Assigned:" $CountFilters
Write-Host

####################################################

write-host "-------------------------------------------------------------------"
Write-Host "Evaluation complete..." -ForegroundColor Green
write-host "-------------------------------------------------------------------"
Write-Host
