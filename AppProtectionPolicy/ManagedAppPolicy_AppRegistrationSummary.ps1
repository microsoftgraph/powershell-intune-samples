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
            [Parameter(Mandatory = $true)]
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
    
        if ($AadModule.count -gt 1) {
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
            # Checking if there are multiple versions of the same module found
    
            if ($AadModule.count -gt 1) {
    
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
    
            $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if ($authResult.AccessToken) {
    
                # Creating header for Authorization token
    
                $authHeader = @{
                    'Content-Type'  = 'application/json'
                    'Authorization' = "Bearer " + $authResult.AccessToken
                    'ExpiresOn'     = $authResult.ExpiresOn
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
    
    Function Get-ManagedAppPolicyRegistrationSummary() {
    
    <#
    .SYNOPSIS
    This function is used to download App Protection Report for iOS and Android.
    .DESCRIPTION
    The function connects to the Graph API Interface and gets the ManagedAppRegistrationSummary
    .EXAMPLE
    Get-ManagedAppPolicyRegistrationSummary -ReportType Android_iOS
    Returns any managed app policies configured in Intune
    .NOTES
    NAME: Get-ManagedAppPolicyRegistrationSummary
    #>
    
        [cmdletbinding()]
    
        param
        (
            [ValidateSet("Android_iOS", "WIP_WE", "WIP_MDM")]
            $ReportType,
            $NextPage
        )
    
        $graphApiVersion = "Beta"
        $Stoploop = $false
        [int]$Retrycount = "0"
        do{
        try {
        
            if ($ReportType -eq "" -or $ReportType -eq $null) {
                $ReportType = "Android_iOS"
        
            }
            elseif ($ReportType -eq "Android_iOS") {
        
                $Resource = "/deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"
                if ($NextPage -ne "" -and $NextPage -ne $null) {
                    $Resource += "&seek=$NextPage"
                }
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        
            }
    
            elseif ($ReportType -eq "WIP_WE") {
        
                $Resource = "deviceAppManagement/managedAppStatuses('windowsprotectionreport')"
                if ($NextPage -ne "" -and $NextPage -ne $null) {
                    $Resource += "&seek=$NextPage"
                }
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        
            }
    
            elseif ($ReportType -eq "WIP_MDM") {
        
                $Resource = "deviceAppManagement/mdmWindowsInformationProtectionPolicies"
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }
            $Stoploop = $true
        }
    
        catch {
    
            $ex = $_.Exception
    
            # Retry 4 times if 503 service time out
            if($ex.Response.StatusCode.value__ -eq "503") {
                $Retrycount = $Retrycount + 1
                $Stoploop = $Retrycount -gt 3
                if($Stoploop -eq $false) {
                    Start-Sleep -Seconds 5
                    continue
                }
            }
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            $Stoploop = $true
            break
        }
    }
    while ($Stoploop -eq $false)
    
    }
    
    ####################################################
    
    Function Test-AuthToken(){
    
        # Checking if authToken exists before running authentication
        if ($global:authToken) {
    
            # Setting DateTime to Universal time to work in all timezones
            $DateTime = (Get-Date).ToUniversalTime()
    
            # If the authToken exists checking when it expires
            $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
    
            if ($TokenExpires -le 0) {
    
                write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
                write-host
    
                # Defining User Principal Name if not present
    
                if ($User -eq $null -or $User -eq "") {
    
                    $global:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                    Write-Host
    
                }
    
                $global:authToken = Get-AuthToken -User $User
    
            }
        }
    
        # Authentication doesn't exist, calling Get-AuthToken function
    
        else {
    
            if ($User -eq $null -or $User -eq "") {
    
                $global:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host
    
            }
    
            # Getting the authorization token
            $global:authToken = Get-AuthToken -User $User
    
        }
    }
    
    ####################################################
    
    Test-AuthToken
    
    ####################################################
    
    Write-Host
    
    $ExportPath = Read-Host -Prompt "Please specify a path to export the policy data to e.g. C:\IntuneOutput"
    
    # If the directory path doesn't exist prompt user to create the directory
    
    if (!(Test-Path "$ExportPath")) {
    
        Write-Host
        Write-Host "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow
    
        $Confirm = read-host
    
        if ($Confirm -eq "y" -or $Confirm -eq "Y") {
    
            new-item -ItemType Directory -Path "$ExportPath" | Out-Null
            Write-Host
    
        }
    
        else {
    
            Write-Host "Creation of directory path was cancelled..." -ForegroundColor Red
            Write-Host
            break
    
        }
    
    }
    
    Write-Host
    
    ####################################################
    
    $AppType = Read-Host -Prompt "Please specify the type of report [Android_iOS, WIP_WE, WIP_MDM]"
    
    if($AppType -eq "Android_iOS" -or $AppType -eq "WIP_WE" -or $AppType -eq "WIP_MDM") {
                
        Write-Host
        write-host "Running query against Microsoft Graph to download App Protection Report for '$AppType'.." -f Yellow
    
        $ofs = ','
        $stream = [System.IO.StreamWriter]::new("$ExportPath\AppRegistrationSummary_$AppType.csv", $false, [System.Text.Encoding]::UTF8)
        $ManagedAppPolicies = Get-ManagedAppPolicyRegistrationSummary -ReportType $AppType
        $stream.WriteLine([string]($ManagedAppPolicies.content.header | % {$_.columnName } ))
    
        do {
            Test-AuthToken
    
            write-host "Your data is being downloaded for '$AppType'..."
            $MoreItem = $ManagedAppPolicies.content.skipToken -ne "" -and $ManagedAppPolicies.content.skipToken -ne $null
            
            foreach ($SummaryItem in $ManagedAppPolicies.content.body) {
    
                $stream.WriteLine([string]($SummaryItem.values -replace ",","."))
            }
            
            if ($MoreItem){
    
                $ManagedAppPolicies = Get-ManagedAppPolicyRegistrationSummary -ReportType $AppType -NextPage ($ManagedAppPolicies.content.skipToken)
            }
    
        } while ($MoreItem)
        
        $stream.close()
        
        write-host
        
    }
        
    else {
        
        Write-Host "AppType isn't a valid option..." -ForegroundColor Red
        Write-Host
        
    }
