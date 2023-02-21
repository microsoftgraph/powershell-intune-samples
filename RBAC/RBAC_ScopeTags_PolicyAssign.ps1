
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

#This needs to be changed for DOD to "https://graph.microsoft.com"
$resourceAppIdURI = "https://graph.microsoft.com"

#This needs to be changed for DOD to "https://login.microsoftonline.com/$Tenant"
$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.comerIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

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
    [switch]$Win10,
    $id
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
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("android") }

        }

        elseif($iOS){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("ios") }

        }

        elseif($Win10){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("windows10CompliancePolicy") }

        }

        elseif($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        elseif($id){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id`?`$expand=assignments,scheduledActionsForRule(`$expand=scheduledActionConfigurations)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

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
    $name,
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"

    try {

        if($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        elseif($id){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
           $results=Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
		$value=$results.value
		$pages=$results.'@odata.nextlink'
		while($null -ne $pages){
		$additional=(Invoke-RestMethod -Uri $pages -Headers $authToken -Method Get)
		if($pages){
        		$value+=$additional.Value
			$pages=$additional."@odata.nextlink"
		}
		}
		return $value
        
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

Function Get-DeviceConfigurationAdminTemplates(){

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
    $name,
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/groupPolicyConfigurations"

    try {

        if($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        elseif($id){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

        $results=Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
		$value=$results.value
		$pages=$results.'@odata.nextlink'
		while($null -ne $pages){
		$additional=(Invoke-RestMethod -Uri $pages -Headers $authToken -Method Get)
		if($pages){
        		$value+=$additional.Value
			$pages=$additional."@odata.nextlink"
		}
		}
		return $value
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

Function Get-DeviceConfigurationSettingsCatalog(){

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
    $name,
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/configurationPolicies"

    try {

        if($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'Name').contains("$Name") }

        }

        elseif($id){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

		$results=Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
		$value=$results.value
		$pages=$results.'@odata.nextlink'
		while($null -ne $pages){
		$additional=(Invoke-RestMethod -Uri $pages -Headers $authToken -Method Get)
		if($pages){
        		$value+=$additional.Value
			$pages=$additional."@odata.nextlink"
		}
		}
		return $value
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

Function Update-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to update a device compliance policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and updates a device compliance policy
.EXAMPLE
Update-DeviceCompliancePolicy -id $Policy.id -Type $Type -ScopeTags "1"
Updates a device configuration policy in Intune
.NOTES
NAME: Update-DeviceCompliancePolicy
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $id,
    [Parameter(Mandatory=$true)]
    $Type,
    [Parameter(Mandatory=$true)]
    $ScopeTags
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceCompliancePolicies/$id"

    try {
     
        if($ScopeTags -eq "" -or $ScopeTags -eq $null){

$JSON = @"

{
  "@odata.type": "$Type",
  "roleScopeTagIds": []
}

"@
        }

        else {

            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value "$Type"
            $object | Add-Member -MemberType NoteProperty -Name 'roleScopeTagIds' -Value @($ScopeTags)
            $JSON = $object | ConvertTo-Json

        }

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $JSON -ContentType "application/json"

        Start-Sleep -Milliseconds 100

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

Function Update-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to update a device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and updates a device configuration policy
.EXAMPLE
Update-DeviceConfigurationPolicy -id $Policy.id -Type $Type -ScopeTags "1"
Updates an device configuration policy in Intune
.NOTES
NAME: Update-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $id,
    [Parameter(Mandatory=$true)]
    $Type,
    [Parameter(Mandatory=$true)]
    $ScopeTags
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceConfigurations/$id"

    try {
     
        if($ScopeTags -eq "" -or $ScopeTags -eq $null){

$JSON = @"

{
  "@odata.type": "$Type",
  "roleScopeTagIds": []
}

"@
        }

        else {

            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value "$Type"
            $object | Add-Member -MemberType NoteProperty -Name 'roleScopeTagIds' -Value @($ScopeTags)
            $JSON = $object | ConvertTo-Json

        }

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $JSON -ContentType "application/json"

        Start-Sleep -Milliseconds 100

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

Function Update-DeviceConfigurationAdminTemplate(){

<#
.SYNOPSIS
This function is used to update a device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and updates a device configuration policy
.EXAMPLE
Update-DeviceConfigurationPolicy -id $Policy.id -Type $Type -ScopeTags "1"
Updates an device configuration policy in Intune
.NOTES
NAME: Update-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $id,
   # [Parameter(Mandatory=$true)]
   # $Type,
    [Parameter(Mandatory=$true)]
    $ScopeTags
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/groupPolicyConfigurations/$id"

    try {
     
        if($ScopeTags -eq "" -or $ScopeTags -eq $null){

$JSON = @"

{

  "roleScopeTagIds": []
}

"@
#took this out of the jason config above just above "roleScopeTagIDs"    "@odata.type": "$Type",
        }

        else {

            $object = New-Object -TypeName PSObject
            #$object | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value "$Type"
            $object | Add-Member -MemberType NoteProperty -Name 'roleScopeTagIds' -Value @($ScopeTags)
            $JSON = $object | ConvertTo-Json

        }

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $JSON -ContentType "application/json"

        Start-Sleep -Milliseconds 100

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

Function Update-DeviceConfigurationSettingsCatalog(){

<#
.SYNOPSIS
This function is used to update a device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and updates a device configuration policy
.EXAMPLE
Update-DeviceConfigurationPolicy -id $Policy.id -Type $Type -ScopeTags "1"
Updates an device configuration policy in Intune
.NOTES
NAME: Update-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $id,
   # [Parameter(Mandatory=$true)]
   # $Type,
    [Parameter(Mandatory=$true)]
    $ScopeTags
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/configurationPolicies/$id"

    try {
     
        if($ScopeTags -eq "" -or $ScopeTags -eq $null){

$JSON = @"

{

  "roleScopeTagIds": []
}

"@
#took this out of the jason config above just above "roleScopeTagIDs"    "@odata.type": "$Type",
        }

        else {

            $object = New-Object -TypeName PSObject
            #$object | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value "$Type"
            $object | Add-Member -MemberType NoteProperty -Name 'roleScopeTagIds' -Value @($ScopeTags)
            $JSON = $object | ConvertTo-Json

        }

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $JSON -ContentType "application/json"

        Start-Sleep -Milliseconds 100

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

Function Get-RBACScopeTag(){

<#
.SYNOPSIS
This function is used to get scope tags using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets scope tags
.EXAMPLE
Get-RBACScopeTag -DisplayName "Test"
Gets a scope tag with display Name 'Test'
.NOTES
NAME: Get-RBACScopeTag
#>

[cmdletbinding()]
    
param
(
    [Parameter(Mandatory=$false)]
    $DisplayName
)

# Defining Variables
$graphApiVersion = "beta"
$Resource = "deviceManagement/roleScopeTags"

    try {

        if($DisplayName){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=displayName eq '$DisplayName'"
            $Result = (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken).Value

        }

        else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

            
           # $Result = (Invoke-RestMethod -Uri $uri -Method Get -Headers $authToken).Value

            $results=Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
		$Result=$results.value
		$pages=$results.'@odata.nextlink'
		while($null -ne $pages){
		$additional=(Invoke-RestMethod -Uri $pages -Headers $authToken -Method Get)
		if($pages){
        		$Result+=$additional.Value
			$pages=$additional."@odata.nextlink"
		}
		}
		return $Result

        }

    return $Result

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
    throw
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

#Write-Host "Are you sure you want to add Scope Tags to all Configuration and Compliance Policies? Y or N?"
#$Confirm = read-host
$Confirm = "Y"
if($Confirm -eq "y" -or $Confirm -eq "Y"){

    Write-Host "Checking if any Scope Tags have been created..."
    Write-Host

    $ScopeTags = Get-RBACScopeTag

    #Modify here so we only work with 1 scope tag at a time instead of all the existing ScopeTags. We do need the '*' as we are using the -like operator. May want to put user input reads to type the Tag name
    Write-host "Please type the Scope Tag you would like to apply (Full and correct scope Tag name)"
    #region ScopeTags Menu

Write-Host

$ScopeTags1 = (Get-RBACScopeTag).displayName | Sort-Object

if($ScopeTags1){

Write-Host "Please specify Scope Tag you want to add to all users / devices in AAD Group:" -ForegroundColor Yellow

$menu = @{}

for ($i=1;$i -le $ScopeTags1.count; $i++) 
{ Write-Host "$i. $($ScopeTags1[$i-1])" 
$menu.Add($i,($ScopeTags1[$i-1]))}

Write-Host
$ans = Read-Host 'Enter Scope Tag id (Numerical value)'

if($ans -eq "" -or $ans -eq $null){

    Write-Host "Scope Tag can't be null, please specify a valid Scope Tag..." -ForegroundColor Red
    Write-Host
    break

}

elseif(($ans -match "^[\d\.]+$") -eq $true){

$selection = $menu.Item([int]$ans)

    if($selection){

        $ScopeTagId = (Get-RBACScopeTag | Where-Object { $_.displayName -eq "$selection" }).id
       $inTag= $selection
    }

    else {

        Write-Host "Scope Tag selection invalid, please specify a valid Scope Tag..." -ForegroundColor Red
        Write-Host
        break

    }

}

else {

    Write-Host "Scope Tag not an integer, please specify a valid scope tag..." -ForegroundColor Red
    Write-Host
    break

}

Write-Host

}

else {

    Write-Host "No Scope Tags created, script can't continue..." -ForegroundColor Red
    Write-Host
    break

}

#endregion
    
    

    $ScopeTags = $ScopeTags | ?{$_.displayname -eq $inTag}

    if($ScopeTags){

        Write-Host "Scope Tags found..." -ForegroundColor Green
        Write-Host

        foreach($ScopeTag in $ScopeTags){

        $ScopeTag_DN = $ScopeTag.displayName
        $ScopeTagId = $ScopeTag.id

        Write-Host "Checking Scope Tag '$ScopeTag_DN'..." -ForegroundColor Cyan

        ####################################################
        
        #region Device Compliance Policies

        Write-Host "Type the pattern name of the Compliance Policies you'd like to apply the ScopeTag provided (Compliance Policy name is case sensitive)"
        $inCP=read-host
# This is where we update the Complicance Policy names so it only targets anything containing the specified text, no need for '*' as we are using contains operator
        $CPs = Get-DeviceCompliancePolicy | Where-Object { ($_.displayName).contains($inCP) } | Sort-Object displayName
        if($CPs){
            write-host "These are the identified Compliance Policies that would be tagged with $($ScopeTag.DisplayName)"
            foreach($cpls in $CPs){
            write-host $CPls.displayName -foregroundcolor Cyan }
            write-host "Are you sure you want to proceed (Y/N)?"
            $answerCP=read-host
        }
        else
        {
            Write-Host "There were no Compliance Policies that matched your name pattern" -foregroundcolor Red
        }

            if(($CPs) -and (($answerCP -eq "Y") -or ($answerCP -eq "y"))){

                foreach($Policy in $CPs){
        
                    $CP = Get-DeviceCompliancePolicy -id $Policy.id

                    $CP_DN = $CP.displayName

                    if($CP.roleScopeTagIds){

                        if(!($CP.roleScopeTagIds).contains("$ScopeTagId")){

                            $ST = @($CP.roleScopeTagIds) + @("$ScopeTagId")

                            $Result = Update-DeviceCompliancePolicy -id $Policy.id -Type $Policy.'@odata.type' -ScopeTags $ST

                            if($Result -eq ""){

                                Write-Host "Compliance Policy '$CP_DN' patched with '$ScopeTag_DN' ScopeTag..." -ForegroundColor Green

                            }

                        }

                        else {

                            Write-Host "Scope Tag '$ScopeTag_DN' already assigned to '$CP_DN'..." -ForegroundColor Red

                        }

                    }

                    else {

                        $ST = @("$ScopeTagId")

                        $Result = Update-DeviceCompliancePolicy -id $Policy.id -Type $Policy.'@odata.type' -ScopeTags $ST

                        if($Result -eq ""){

                            Write-Host "Compliance Policy '$CP_DN' patched with '$ScopeTag_DN' ScopeTag..." -ForegroundColor Green

                        }

                    }

                }

            }

            Write-Host

        #endregion

        ####################################################

        #region Device Configuration Policies

        Write-Host "Type the pattern name of the Configuration Profiles you'd like to apply the scope tag provided (Configuration profile name is case sensitive)"
        $inDCP=read-host

#Update this displayName.contains with the name/names or wildcard of the Configuration profiles that we want to update no need for a '*' in the contains section
        $DCPs = Get-DeviceConfigurationPolicy | Where-Object { ($_.displayName).contains($inDCP) } | Sort-Object displayName
        $AdmTemp=Get-DeviceConfigurationAdminTemplates | Where-Object { ($_.displayName).contains($inDCP) } | Sort-Object displayName
	  $SettCat=get-deviceconfigurationsettingscatalog | Where-Object { ($_.Name).contains($inDCP) } | Sort-Object Name


if(($DCPs) -or ($AdmTemp) -or ($SettCat)){
            write-host "These are the identified Configuration Profiles that would be tagged with $($ScopeTag.DisplayName)"
            foreach($pol in $DCPs){write-host $pol.displayName -foregroundcolor Cyan}
            if($AdmTemp){foreach($templ in $AdmTemp){write-host $templ.displayName -foregroundcolor Cyan}}
            if($SettCat){foreach($templ in $SettCat){write-host $templ.Name -foregroundcolor Cyan}}
            write-host "Are you sure you want to proceed (Y/N)?"
            $answerDCP=read-host
        }
        else
        {
            Write-host "There were no Configuration profiles that matched your name pattern" -foregroundcolor Red
        }

            if(($DCPs) -and (($answerDCP -eq "Y") -or ($answerDCP -eq "y"))){

                foreach($Policy in $DCPs){
        
                    $DCP = Get-DeviceConfigurationPolicy -id $Policy.id

                    $DCP_DN = $DCP.displayName

                    if($DCP.roleScopeTagIds){

                        if(!($DCP.roleScopeTagIds).contains("$ScopeTagId")){

                            $ST = @($DCP.roleScopeTagIds) + @("$ScopeTagId")

                            $Result = Update-DeviceConfigurationPolicy -id $Policy.id -Type $Policy.'@odata.type' -ScopeTags $ST

                            if($Result -eq ""){

                                Write-Host "Configuration Policy '$DCP_DN' patched with '$ScopeTag_DN' ScopeTag..." -ForegroundColor Green

                            }

                        }

                        else {

                            Write-Host "Scope Tag '$ScopeTag_DN' already assigned to '$DCP_DN'..." -ForegroundColor Red

                        }

                    }

                    else {

                        $ST = @("$ScopeTagId")

                        $Result = Update-DeviceConfigurationPolicy -id $Policy.id -Type $Policy.'@odata.type' -ScopeTags $ST

                        if($Result -eq ""){

                            Write-Host "Configuration Policy '$DCP_DN' patched with '$ScopeTag_DN' ScopeTag..." -ForegroundColor Green

                        }

                    }

                }

            }

if(($AdmTemp) -and (($answerDCP -eq "Y") -or ($answerDCP -eq "y"))){

                foreach($Policy in $AdmTemp){
        
                    $DCP = Get-DeviceConfigurationAdminTemplates -id $Policy.id

                    $DCP_DN = $DCP.displayName

                    if($DCP.roleScopeTagIds){

                        if(!($DCP.roleScopeTagIds).contains("$ScopeTagId")){

                            $ST = @($DCP.roleScopeTagIds) + @("$ScopeTagId")

                            $Result = Update-DeviceConfigurationAdminTemplate -id $DCP.id -ScopeTags $ST

                            if($Result.displayname -eq $DCP.displayname){

                                Write-Host "Configuration Policy '$DCP_DN' patched with '$ScopeTag_DN' ScopeTag..." -ForegroundColor Green

                            }

                        }

                        else {

                            Write-Host "Scope Tag '$ScopeTag_DN' already assigned to '$DCP_DN'..." -ForegroundColor Red

                        }

                    }

                    else {

                        $ST = @("$ScopeTagId")

                        $Result = Update-DeviceConfigurationAdminTemplate -id $Policy.id -ScopeTags $ST

                        if($Result.displayname -eq $Policy.displayname){

                            Write-Host "Configuration Policy '$DCP_DN' patched with '$ScopeTag_DN' ScopeTag..." -ForegroundColor Green

                        }

                    }

                }

            }
            Write-Host

if(($SettCat) -and (($answerDCP -eq "Y") -or ($answerDCP -eq "y"))){

                foreach($Policy in $SettCat){
        
                    $DCP = Get-DeviceConfigurationsettingscatalog -id $Policy.id

                    $DCP_DN = $DCP.Name

                    if($DCP.roleScopeTagIds){

                        if(!($DCP.roleScopeTagIds).contains("$ScopeTagId")){

                            $ST = @($DCP.roleScopeTagIds) + @("$ScopeTagId")

                            $Result = Update-DeviceConfigurationsettingscatalog -id $DCP.id -ScopeTags $ST

                            if($Result -eq ""){

                                Write-Host "Configuration Policy '$DCP_DN' patched with '$ScopeTag_DN' ScopeTag..." -ForegroundColor Green

                            }

                        }

                        else {

                            Write-Host "Scope Tag '$ScopeTag_DN' already assigned to '$DCP_DN'..." -ForegroundColor Red

                        }

                    }

                    else {

                        $ST = @("$ScopeTagId")

                        $Result = Update-DeviceConfigurationsettingscatalog -id $DCP.id -ScopeTags $ST

                        if($Result.name -eq $DCP.name){

                            Write-Host "Configuration Policy '$DCP_DN' patched with '$ScopeTag_DN' ScopeTag..." -ForegroundColor Green

                        }

                    }

                }

            }
            Write-Host


        #endregion

        ####################################################

        }

    }

    else {

        Write-Host "No Scope Tags found with that name..." -ForegroundColor Red

    }

}

else {

    Write-Host "Addition of Scope Tags to all Configuration and Compliance Policies was cancelled"

}

Write-Host
