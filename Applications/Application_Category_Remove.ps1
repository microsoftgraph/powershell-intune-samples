
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

Function Get-ApplicationCategory(){

<#
.SYNOPSIS
This function is used to get application categories from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any application category
.EXAMPLE
Get-ApplicationCategory
Returns any application categories configured in Intune
.NOTES
NAME: Get-ApplicationCategory
#>

[cmdletbinding()]

param
(
    $Name
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileAppCategories"

    try {

        if($Name){

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

Function Remove-ApplicationCategory(){

<#
.SYNOPSIS
This function is used to remove an application category from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and removes an application category
.EXAMPLE
Remove-ApplicationCategory -id $id
Removes an application category configured in Intune
.NOTES
NAME: Remove-ApplicationCategory
#>

[cmdletbinding()]

param
(
    $id
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileAppCategories"

    try {

        if($id -eq "" -or $id -eq $null){

        write-host "No id specified for application category, can't remove application category..." -f Red
        write-host "Please specify id for application category..." -f Red
        break

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-RestMethod -Uri $uri –Headers $authToken –Method Delete

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

$App = Get-ApplicationCategory -Name "LOB Apps 2" | Where-Object { $_.lastModifiedDateTime -ne "0001-01-01T00:00:00Z" }

    if($App){

        if(@($App).count -gt 1){
        
        Write-Host "More than one Application Categrory has been found, please specify a single Application Category..." -ForegroundColor Red
        Write-Host

        }

        elseif(@($App).count -eq 1){

        Write-Host "Removing Application Category" $App.displayName -ForegroundColor Yellow
        Remove-ApplicationCategory -id $App.id

        }

    }

    else {

    Write-Host "Application Category can't be found or its an inbuilt category name that can't be removed..." -ForegroundColor Yellow
    Write-Host

    }