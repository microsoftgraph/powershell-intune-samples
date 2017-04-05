
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
.REFERENCE
Acknowledgement to Paolo Marques
https://blogs.technet.microsoft.com/paulomarques/2016/03/21/working-with-azure-active-directory-graph-api-from-powershell/

#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $TenantName
)
 
$adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
 
$adalforms = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
 
    if((test-path "$adal") -eq $false){
 
    write-host
    write-host "Azure Powershell module not installed..." -f Red
    write-host "Please install Azure SDK for Powershell - https://azure.microsoft.com/en-us/downloads/" -f Yellow
    write-host "Script can't continue..." -f Red
    write-host
    exit
 
    }
 
[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
 
[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
 
$clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
 
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
 
$resourceAppIdURI = "https://graph.microsoft.com"
 
$authority = "https://login.windows.net/$TenantName"
 
    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
 
    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $authResult = $authContext.AcquireToken($resourceAppIdURI,$clientId,$redirectUri, "Always")

        # Building Rest Api header with authorization token
        $authHeader = @{
        'Content-Type'='application\json'
        'Authorization'=$authResult.CreateAuthorizationHeader()
        'ExpiresOn'=$authResult.ExpiresOn
        }

    return $authHeader

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
NAME: Test-AuthHeader
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

Function Add-AndroidApplication(){

<#
.SYNOPSIS
This function is used to add an Android application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an Android application from the itunes store
.EXAMPLE
Add-AndroidApplication -JSON $JSON -IconURL pathtourl
Adds an Android application into Intune using an icon from a URL
.NOTES
NAME: Add-AndroidApplication
#>

[cmdletbinding()]

param
(
    $JSON,
    $IconURL
)

$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

    try {

        if(!$JSON){

        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }


        if($IconURL){

        write-verbose "Icon specified: $IconURL"

            if(!(test-path "$IconURL")){

            write-host "Icon Path '$IconURL' doesn't exist..." -ForegroundColor Red
            Write-Host "Please specify a valid path..." -ForegroundColor Red
            Write-Host
            break

            }

        $iconResponse = Invoke-WebRequest "$iconUrl"
        $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
        $iconExt = ([System.IO.Path]::GetExtension("$iconURL")).replace(".","")
        $iconType = "image/$iconExt"

        Write-Verbose "Updating JSON to add Icon Data"

        $U_JSON = ConvertFrom-Json $JSON

        $U_JSON.largeIcon.type = "$iconType"
        $U_JSON.largeIcon.value = "$base64icon"

        $JSON = ConvertTo-Json $U_JSON

        Write-Verbose $JSON

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken

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

            if($tenant -eq $null -or $tenant -eq ""){

            $tenant = Read-Host -Prompt "Please specify your tenant name"
            Write-Host

            }

        $global:authToken = Get-AuthToken -TenantName $tenant

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($tenant -eq $null -or $tenant -eq ""){

    # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

    $tenant = Read-Host -Prompt "Please specify your tenant name"

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -TenantName $tenant

}

#endregion

####################################################
# Creating Icon for Android App
####################################################

$iconUrl_Outlook = "C:\IntuneIcons\Outlook.png"
$iconUrl_Excel = "C:\IntuneIcons\Excel.PNG"
$iconUrl_Browser = "C:\IntuneIcons\IntuneBrowser.PNG"

if(!(Test-Path "$iconUrl_Outlook")){

Write-Host "Icon path for '$iconUrl_Outlook' doesn't exist, please specify a valid path..." -ForegroundColor Red
Write-Host
break

}

if(!(Test-Path "$iconUrl_Excel")){

Write-Host "Icon path for '$iconUrl_Excel' doesn't exist, please specify a valid path..." -ForegroundColor Red
Write-Host
break

}

if(!(Test-Path "$iconUrl_Browser")){

Write-Host "Icon path for '$iconUrl_Browser' doesn't exist, please specify a valid path..." -ForegroundColor Red
Write-Host
break

}

##################################################

$Outlook = @"

{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Outlook",
  "description": "Microsoft Outlook",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.outlook&hl=en",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }

}

"@

##################################################

$Excel = @"

{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Excel",
  "description": "Microsoft Excel",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.excel&hl=en",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }

}

"@

##################################################

$Browser = @"

{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Intune Managed Browser",
  "description": "Intune Managed Browser",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.intune.mam.managedbrowser&hl=en",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }

}

"@

##################################################

write-host "Publishing" ($Outlook | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Outlook = Add-AndroidApplication -JSON $Outlook -IconURL "$iconUrl_Outlook"

Write-Host "Application created as $($Create_Outlook.displayName)/$($create_Outlook.id)"
Write-Host

##################################################

write-host "Publishing" ($Browser | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Browser = Add-AndroidApplication -JSON $Browser -IconURL "$iconUrl_Browser"

Write-Host "Application created as $($Create_Browser.displayName)/$($create_Browser.id)"
Write-Host

##################################################

write-host "Publishing" ($Excel | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Excel = Add-AndroidApplication -JSON $Excel -IconURL "$iconUrl_Excel"

Write-Host "Application created as $($Create_Excel.displayName)/$($create_Excel.id)"
Write-Host
