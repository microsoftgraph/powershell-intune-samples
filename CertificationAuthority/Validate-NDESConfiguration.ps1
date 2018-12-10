
<#

.SYNOPSIS
Highlights configuration problems on an NDES server, as configured for use with Intune Standalone SCEP certificates.

.DESCRIPTION
Validate-NDESConfig looks at the configuration of your NDES server and ensures it aligns to the "Configure and manage SCEP 
certificates with Intune" article. 

.NOTE This script is used purely to validate the configuration. All remedial tasks will need to be carried out manually.
Where possible, a link and section description will be provided.

.EXAMPLE
.\Validate-NDESConfiguration -NDESServiceAccount Contoso\NDES_SVC.com -IssuingCAServerFQDN IssuingCA.contoso.com -SCEPUserCertTemplate SCEPGeneral

.EXAMPLE
.\Validate-NDESConfiguration -help

.LINK
https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure

#>

[CmdletBinding(DefaultParameterSetName="NormalRun")]

Param(
[parameter(Mandatory=$true,ParameterSetName="NormalRun")]
[alias("sa")]
[ValidateScript({
    if ($_ -match ".\\."){

        $True
    
    }

    else {

    Throw "Please use the format Domain\Username for the NDES Service Account variable."

    }

    $EnteredDomain = $_.split("\")
    $ads = New-Object -ComObject ADSystemInfo
    $Domain = $ads.GetType().InvokeMember('DomainShortName','GetProperty', $Null, $ads, $Null)
    
        if ($EnteredDomain -like "$Domain") {

        $True

        }

        else {
   
        Throw "Incorrect Domain. Ensure domain is '$($Domain)\<USERNAME>'"

        }

    }
)]
[string]$NDESServiceAccount,

[parameter(Mandatory=$true,ParameterSetName="NormalRun")]
[alias("ca")]
[ValidateScript({
    $Domain = (Get-WmiObject Win32_ComputerSystem).domain
        if ($_ -match $Domain) {

        $True

        }

        else {
   
        Throw "The Network Device Enrollment Server and the Certificate Authority are not members of the same Active Directory domain. This is an unsupported configuration."

        }

    }
)]
[string]$IssuingCAServerFQDN,

[parameter(Mandatory=$true,ParameterSetName="NormalRun")]
[alias("t")]
[string]$SCEPUserCertTemplate,

[parameter(ParameterSetName="Help")]
[alias("h","?","/?")]
[switch]$help,

[parameter(ParameterSetName="Help")]
[alias("u")]
[switch]$usage  

    
)

#######################################################################

Function Log-ScriptEvent {

[CmdletBinding()]

Param(
      [parameter(Mandatory=$True)]
      [String]$LogFilePath,

      [parameter(Mandatory=$True)]
      [String]$Value,

      [parameter(Mandatory=$True)]
      [String]$Component,

      [parameter(Mandatory=$True)]
      [ValidateRange(1,3)]
      [Single]$Severity
      )

$DateTime = New-Object -ComObject WbemScripting.SWbemDateTime 
$DateTime.SetVarDate($(Get-Date))
$UtcValue = $DateTime.Value
$UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)

$LogLine =  "<![LOG[$Value]LOG]!>" +`
            "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " +`
            "date=`"$(Get-Date -Format M-d-yyyy)`" " +`
            "component=`"$Component`" " +`
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            "type=`"$Severity`" " +`
            "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
            "file=`"`">"

Add-Content -Path $LogFilePath -Value $LogLine

}

##########################################################################################################

function Show-Usage {

    Write-Host
    Write-Host "-help                       -h         Displays the help."
    Write-Host "-usage                      -u         Displays this usage information."
    Write-Host "-NDESExternalHostname       -ed        External DNS name for the NDES server (SSL certificate subject will be checked for this. It should be in the SAN of the certificate if" 
    write-host "                                       clients communicate directly with the NDES server)"
    Write-Host "-NDESServiceAccount         -sa        Username of the NDES service account. Format is Domain\sAMAccountName, such as Contoso\NDES_SVC."
    Write-Host "-IssuingCAServerFQDN        -ca        Name of the issuing CA to which you'll be connecting the NDES server.  Format is FQDN, such as 'MyIssuingCAServer.contoso.com'."
    Write-Host "-SCEPUserCertTemplate       -t         Name of the SCEP Certificate template. Please note this is _not_ the display name of the template. Value should not contain spaces." 
    Write-Host

}

#######################################################################

function Get-NDESHelp {

    Write-Host
    Write-Host "Verifies if the NDES server meets all the required configuration. "
    Write-Host
    Write-Host "The NDES server role is required as back-end infrastructure for Intune Standalone for delivering VPN and Wi-Fi certificates via the SCEP protocol to mobile devices and desktop clients."
    Write-Host "See https://docs.microsoft.com/en-us/intune/certificates-scep-configure."
    Write-Host

}

#######################################################################

    if ($help){

        Get-NDESHelp
        break

    }

    if ($usage){

        Show-Usage
        break
    }

#######################################################################

#Requires -version 3.0
#Requires -RunAsAdministrator

#######################################################################

$parent = [System.IO.Path]::GetTempPath()
[string] $name = [System.Guid]::NewGuid()
New-Item -ItemType Directory -Path (Join-Path $parent $name) | Out-Null
$TempDirPath = "$parent$name"
$LogFilePath = "$($TempDirPath)\Validate-NDESConfig.log"

#######################################################################

#region Proceed with Variables...

    Write-Host
    Write-host "......................................................."
    Write-Host
    Write-Host "NDES Service Account = "-NoNewline 
    Write-Host "$($NDESServiceAccount)" -ForegroundColor Cyan
    Write-host
    Write-Host "Issuing CA Server = " -NoNewline
    Write-Host "$($IssuingCAServerFQDN)" -ForegroundColor Cyan
    Write-host
    Write-Host "SCEP Certificate Template = " -NoNewline
    Write-Host "$($SCEPUserCertTemplate)" -ForegroundColor Cyan
    Write-Host
    Write-host "......................................................."
    Write-Host
    Write-Host "Proceed with variables? [Y]es, [N]o"
    
    $confirmation = Read-Host

#endregion

#######################################################################

    if ($confirmation -eq 'y'){
    Write-Host
    Write-host "......................................................."
    Log-ScriptEvent $LogFilePath "Initializing log file $($TempDirPath)\Validate-NDESConfig.log"  NDES_Validation 1
    Log-ScriptEvent $LogFilePath "Proceeding with variables=YES"  NDES_Validation 1
    Log-ScriptEvent $LogFilePath "NDESServiceAccount=$($NDESServiceAccount)" NDES_Validation 1
    Log-ScriptEvent $LogFilePath "IssuingCAServer=$($IssuingCAServerFQDN)" NDES_Validation 1
    Log-ScriptEvent $LogFilePath "SCEPCertificateTemplate=$($SCEPUserCertTemplate)" NDES_Validation 1

#######################################################################

#region Install RSAT tools, Check if NDES and IIS installed

    if (-not (Get-WindowsFeature ADCS-Device-Enrollment).Installed){
    
    Write-Host "Error: NDES Not installed" -BackgroundColor Red
    write-host "Exiting....................."
    Log-ScriptEvent $LogFilePath "NDES Not installed" NDES_Validation 3
    break

    }

Install-WindowsFeature RSAT-AD-PowerShell | Out-Null

Import-Module ActiveDirectory | Out-Null

    if (-not (Get-WindowsFeature Web-WebServer).Installed){

        $IISNotInstalled = $TRUE
        Write-Warning "IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"
        Write-Host
        Log-ScriptEvent $LogFilePath "IIS is not installed. Some tests will not run as we're unable to import the WebAdministration module"  NDES_Validation 2
    
    }

    else {

        Import-Module WebAdministration | Out-Null

    }

#endregion

#######################################################################

#region checking OS version
    
    Write-Host
    Write-host "Checking Windows OS version..." -ForegroundColor Yellow
    Write-host
    Log-ScriptEvent $LogFilePath "Checking OS Version" NDES_Validation 1

$OSVersion = (Get-CimInstance -class Win32_OperatingSystem).Version
$MinOSVersion = "6.3"

    if ([version]$OSVersion -lt [version]$MinOSVersion){
    
        Write-host "Error: Unsupported OS Version. NDES Requires 2012 R2 and above." -BackgroundColor Red
        Log-ScriptEvent $LogFilePath "Unsupported OS Version. NDES Requires 2012 R2 and above." NDES_Validation 3
        
        } 
    
    else {
    
        Write-Host "Success: " -ForegroundColor Green -NoNewline
        Write-Host "OS Version " -NoNewline
        write-host "$($OSVersion)" -NoNewline -ForegroundColor Cyan
        write-host " supported."
        Log-ScriptEvent $LogFilePath "Server is version $($OSVersion)" NDES_Validation 1
    
    }

#endregion

#######################################################################
    
#region Checking NDES Service Account properties in Active Directory

Write-host
Write-host "......................................................."
Write-Host
Write-host "Checking NDES Service Account properties in Active Directory..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking NDES Service Account properties in Active Directory" NDES_Validation 1

$ADUser = $NDESServiceAccount.split("\")[1]

$ADUserProps = (Get-ADUser $ADUser -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut)

    if ($ADUserProps.enabled -ne $TRUE -OR $ADUserProps.PasswordExpired -ne $false -OR $ADUserProps.LockedOut -eq $TRUE){
        
        Write-Host "Error: Problem with the AD account. Please see output below to determine the issue" -BackgroundColor Red
        Write-Host
        Log-ScriptEvent $LogFilePath "Problem with the AD account. Please see output below to determine the issue"  NDES_Validation 3
        
    }
        
    else {

        Write-Host "Success: " -ForegroundColor Green -NoNewline
        Write-Host "NDES Service Account seems to be in working order:"
        Log-ScriptEvent $LogFilePath "NDES Service Account seems to be in working order"  NDES_Validation 1
        
    }


  
Get-ADUser $ADUser -Properties SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut | fl SamAccountName,enabled,AccountExpirationDate,accountExpires,accountlockouttime,PasswordExpired,PasswordLastSet,PasswordNeverExpires,LockedOut

#endregion

#######################################################################

#region Checking if NDES server is the CA

Write-host "`n.......................................................`n"
Write-host "Checking if NDES server is the CA...`n" -ForegroundColor Yellow
Log-ScriptEvent $LogFilePath "Checking if NDES server is the CA" NDES_Validation 1 

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$CARoleInstalled = (Get-WindowsFeature ADCS-Cert-Authority).InstallState -eq "Installed"

    if ($hostname -match $IssuingCAServerFQDN){
    
        Write-host "Error: NDES is running on the CA. This is an unsupported configuration!" -BackgroundColor Red
        Log-ScriptEvent $LogFilePath "NDES is running on the CA"  NDES_Validation 3
    
    }
    elseif($CARoleInstalled)
    {
        Write-host "Error: NDES server has Certification Authority Role installed. This is an unsupported configuration!" -BackgroundColor Red
        Log-ScriptEvent $LogFilePath "NDES server has Certification Authority Role installed"  NDES_Validation 3
    }
    else {

        Write-Host "Success: " -ForegroundColor Green -NoNewline
        Write-Host "NDES server is not running on the CA"
        Log-ScriptEvent $LogFilePath "NDES server is not running on the CA"  NDES_Validation 1 
    
    }

#endregion

#######################################################################

#region Checking NDES Service Account local permissions

Write-host
Write-host "......................................................."
Write-host
Write-host "Checking NDES Service Account local permissions..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking NDES Service Account local permissions" NDES_Validation 1 

   if ((net localgroup) -match "Administrators"){

    $LocalAdminsMember = ((net localgroup Administrators))

        if ($LocalAdminsMember -like "*$NDESServiceAccount*"){
        
            Write-Warning "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use IIS_IUSERS instead."
            Log-ScriptEvent $LogFilePath "NDES Service Account is a member of the local Administrators group. This will provide the requisite rights but is _not_ a secure configuration. Use IIS_IUSERS instead."  NDES_Validation 2

        }

        else {

            Write-Host "Success: " -ForegroundColor Green -NoNewline
            Write-Host "NDES Service account is not a member of the Local Administrators group"
            Log-ScriptEvent $LogFilePath "NDES Service account is not a member of the Local Administrators group"  NDES_Validation 1
    
        }

    Write-host
    Write-Host "Checking NDES Service account is a member of the IIS_IUSR group..." -ForegroundColor Yellow
    Write-host

    if ((net localgroup) -match "IIS_IUSRS"){

        $IIS_IUSRMembers = ((net localgroup IIS_IUSRS))

        if ($IIS_IUSRMembers -like "*$NDESServiceAccount*"){

            Write-Host "Success: " -ForegroundColor Green -NoNewline
            Write-Host "NDES Service Account is a member of the local IIS_IUSR group" -NoNewline
            Log-ScriptEvent $LogFilePath "NDES Service Account is a member of the local IIS_IUSR group" NDES_Validation 1
    
        }
    
        else {

            Write-Host "Error: NDES Service Account is not a member of the local IIS_IUSR group" -BackgroundColor red
            Log-ScriptEvent $LogFilePath "NDES Service Account is not a member of the local IIS_IUSR group"  NDES_Validation 3 

            Write-host
            Write-host "Checking Local Security Policy for explicit rights via gpedit..." -ForegroundColor Yellow
            Write-Host
            $TempFile = [System.IO.Path]::GetTempFileName()
            & "secedit" "/export" "/cfg" "$TempFile" | Out-Null
            $LocalSecPol = Get-Content $TempFile
            $ADUserProps = Get-ADUser $ADUser
            $NDESSVCAccountSID = $ADUserProps.SID.Value 
            $LocalSecPolResults = $LocalSecPol | Select-String $NDESSVCAccountSID

                if ($LocalSecPolResults -match "SeInteractiveLogonRight" -AND $LocalSecPolResults -match "SeBatchLogonRight" -AND $LocalSecPolResults -match "SeServiceLogonRight"){
            
                    Write-Host "Success: " -ForegroundColor Green -NoNewline
                    Write-Host "NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly."
                    Log-ScriptEvent $LogFilePath "NDES Service Account has been assigned the Logon Locally, Logon as a Service and Logon as a batch job rights explicitly." NDES_Validation 1
                    Write-Host
                    Write-Host "Note:" -BackgroundColor Red -NoNewline
                    Write-Host " The Logon Locally is not required in normal runtime."
                    Write-Host
                    Write-Host "Note:" -BackgroundColor Red -NoNewline
                    Write-Host 'Consider using the IIS_IUSERS group instead of explicit rights as documented under "Step 1 - Create an NDES service account".'
                    write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            
                }
            
                else {

                    Write-Host "Error: NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_." -BackgroundColor red 
                    Write-Host 'Please review "Step 1 - Create an NDES service account".' 
                    write-host "https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
                    Log-ScriptEvent $LogFilePath "NDES Service Account has _NOT_ been assigned the Logon Locally, Logon as a Service or Logon as a batch job rights _explicitly_." NDES_Validation 3
            
                }
    
        }

    }

    else {

        Write-Host "Error: No IIS_IUSRS group exists. Ensure IIS is installed." -BackgroundColor red 
        write-host 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        write-host "https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "No IIS_IUSRS group exists. Ensure IIS is installed." NDES_Validation 3
    
    }

    }

   else {

        Write-Warning "No local Administrators group exists, likely due to this being a Domain Controller. It is not recommended to run NDES on a Domain Controller."
        Log-ScriptEvent $LogFilePath "No local Administrators group exists, likely due to this being a Domain Controller. It is not recommended to run NDES on a Domain Controller." NDES_Validation 2
    
    }

#endregion

#######################################################################

#region Checking Windows Features are installed.

Write-host
Write-Host
Write-host "......................................................."
Write-host
Write-host "Checking Windows Features are installed..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking Windows Features are installed..." NDES_Validation 1

$WindowsFeatures = @("Web-Filtering","Web-Net-Ext45","NET-Framework-45-Core","NET-WCF-HTTP-Activation45","Web-Metabase","Web-WMI")

foreach($WindowsFeature in $WindowsFeatures){

$Feature =  Get-WindowsFeature $WindowsFeature
$FeatureDisplayName = $Feature.displayName

    if($Feature.installed){
    
        Write-host "Success:" -ForegroundColor Green -NoNewline
        write-host "$FeatureDisplayName Feature Installed"
        Log-ScriptEvent $LogFilePath "$($FeatureDisplayName) Feature Installed"  NDES_Validation 1
    
    }

    else {

        Write-Host "Error: $FeatureDisplayName Feature not installed!" -BackgroundColor red 
        Write-Host 'Please review "Step 3.1b - Configure prerequisites on the NDES server".' 
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "$($FeatureDisplayName) Feature not installed"  NDES_Validation 3
    
    }

}

#endregion

#################################################################

#region Checking NDES Install Paramaters

$ErrorActionPreference = "SilentlyContinue"

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking NDES Install Paramaters..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking NDES Install Paramaters" NDES_Validation 1

$InstallParams = @(Get-WinEvent -LogName "Microsoft-Windows-CertificateServices-Deployment/Operational" | Where-Object {$_.id -eq "105"}|
Where-Object {$_.message -match "Install-AdcsNetworkDeviceEnrollmentService"}| Sort-Object -Property TimeCreated -Descending | Select-Object -First 1)

    if ($InstallParams.Message -match '-SigningProviderName "Microsoft Strong Cryptographic Provider"' -AND ($InstallParams.Message -match '-EncryptionProviderName "Microsoft Strong Cryptographic Provider"')) {

        Write-Host "Success: " -ForegroundColor Green -NoNewline
        write-host "Correct CSP used in install parameters"
        Write-host
        Write-Host $InstallParams.Message
        Log-ScriptEvent $LogFilePath "Correct CSP used in install parameters:"  NDES_Validation 1
        Log-ScriptEvent $LogFilePath "$($InstallParams.Message)"  NDES_Eventvwr 1

    }

    else {

        Write-Host "Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP." -BackgroundColor red
        Write-Host
        Write-Host $InstallParams.Message
        Log-ScriptEvent $LogFilePath "Error: Incorrect CSP selected during install. NDES only supports the CryptoAPI CSP"  NDES_Validation 3 
        Log-ScriptEvent $LogFilePath "$($InstallParams.Message)"  NDES_Eventvwr 3
    }

$ErrorActionPreference = "Continue"

#endregion

#################################################################

#region Checking IIS Application Pool health

Write-host
Write-host "......................................................."
Write-host
Write-host "Checking IIS Application Pool health..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking IIS Application Pool health" NDES_Validation 1

    if (-not ($IISNotInstalled -eq $TRUE)){

        # If SCEP AppPool Exists    
        if (Test-Path 'IIS:\AppPools\SCEP'){

        $IISSCEPAppPoolAccount = Get-Item 'IIS:\AppPools\SCEP' | select -expandproperty processmodel | select -Expand username
            
            if ((Get-WebAppPoolState "SCEP").value -match "Started"){
            
                $SCEPAppPoolRunning = $TRUE
            
            }

        }

        else {

            Write-Host "Error: SCEP Application Pool missing!" -BackgroundColor red 
            Write-Host 'Please review "Step 3.1 - Configure prerequisites on the NDES server"'. 
            write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
            Log-ScriptEvent $LogFilePath "SCEP Application Pool missing"  NDES_Validation 3
        
        }
    
        if ($IISSCEPAppPoolAccount -contains "$NDESServiceAccount"){
            
        Write-Host "Success: " -ForegroundColor Green -NoNewline
        Write-Host "Application Pool is configured to use " -NoNewline
        Write-Host "$($IISSCEPAppPoolAccount)"
        Log-ScriptEvent $LogFilePath "Application Pool is configured to use $($IISSCEPAppPoolAccount)"  NDES_Validation 1
            
        }
            
        else {

        Write-Host "Error: Application Pool is not configured to use the NDES Service Account" -BackgroundColor red 
        Write-Host 'Please review "Step 4.1 - Configure NDES for use with Intune".' 
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure" 
        Log-ScriptEvent $LogFilePath "Application Pool is not configured to use the NDES Service Account"  NDES_Validation 3
            
        }
                
        if ($SCEPAppPoolRunning){
                
            Write-Host "Success: " -ForegroundColor Green -NoNewline
            Write-Host "SCEP Application Pool is Started " -NoNewline
            Log-ScriptEvent $LogFilePath "SCEP Application Pool is Started"  NDES_Validation 1
                
        }
                
        else {

            Write-Host "Error: SCEP Application Pool is stopped!" -BackgroundColor red 
            Write-Host "Please start the SCEP Application Pool via IIS Management Console. You should also review the Application Event log output for Errors"
            Log-ScriptEvent $LogFilePath "SCEP Application Pool is stopped"  NDES_Validation 3
                
        }

    }

    else {

        Write-Host "IIS is not installed." -BackgroundColor red
        Log-ScriptEvent $LogFilePath "SCEP Application Pool is stopped"  NDES_Validation 3 

    }

#endregion

#################################################################

#region Checking Request Filtering

Write-Host
Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking Request Filtering (Default Web Site -> Request Filtering -> Edit Feature Setting) has been configured in IIS..." -ForegroundColor Yellow
Write-Host
Log-ScriptEvent $LogFilePath "Checking Request Filtering" NDES_Validation 1

    if (-not ($IISNotInstalled -eq $TRUE)){

        [xml]$RequestFiltering = (c:\windows\system32\inetsrv\appcmd.exe list config "default web site" /section:requestfiltering)

        if ($RequestFiltering.'system.webserver'.security.requestFiltering.requestLimits.maxQueryString -eq "65534"){
    
            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "MaxQueryString Set Correctly"
            Log-ScriptEvent $LogFilePath "MaxQueryString Set Correctly"  NDES_Validation 1    
    
        }
    
        else {

            Write-Host "MaxQueryString not set correctly!" -BackgroundColor red 
            Write-Host 'Please review "Step 4.4 - Configure NDES for use with Intune".'
            write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Log-ScriptEvent $LogFilePath "MaxQueryString not set correctly"  NDES_Validation 3
    
        }

        if ($RequestFiltering.'system.webserver'.security.requestFiltering.requestLimits.maxUrl -eq "65534"){
    
            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "MaxUrl Set Correctly"
            Log-ScriptEvent $LogFilePath "MaxUrl Set Correctly"  NDES_Validation 1
    
        }

        else {
    
            Write-Host "maxUrl not set correctly!" -BackgroundColor red 
            Write-Host 'Please review "Step 4.4 - Configure NDES for use with Intune".'
            write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure'"
            Log-ScriptEvent $LogFilePath "maxUrl not set correctly"  NDES_Validation 3 

        }

     }

    else {

        Write-Host "IIS is not installed." -BackgroundColor red
        Log-ScriptEvent $LogFilePath "IIS is not installed"  NDES_Validation 3 

    }

#endregion

#################################################################

#region Checking registry has been set to allow long URLs

Write-host
Write-host "......................................................."
Write-host
Write-Host 'Checking registry "HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters" has been set to allow long URLs...' -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking registry (HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters) has been set to allow long URLs" NDES_Validation 1

    if (-not ($IISNotInstalled -eq $TRUE)){

        If ((Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength).MaxfieldLength -notmatch "65534"){

            Write-Host "Error: MaxFieldLength not set to 65534 in the registry!" -BackgroundColor red
            Write-Host 
            Write-Host 'Please review "Step 4.3 - Configure NDES for use with Intune".'
            write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Log-ScriptEvent $LogFilePath "MaxFieldLength not set to 65534 in the registry" NDES_Validation 3
        } 

        else {

            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "MaxFieldLength set correctly"
            Log-ScriptEvent $LogFilePath "MaxFieldLength set correctly"  NDES_Validation 1
    
        }
		
        if ((Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes).MaxRequestBytes -notmatch "65534"){

            Write-Host "MaxRequestBytes not set to 65534 in the registry!" -BackgroundColor red
            Write-Host 
            Write-Host 'Please review "Step 4.3 - Configure NDES for use with Intune".'
            write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure'"
            Log-ScriptEvent $LogFilePath "MaxRequestBytes not set to 65534 in the registry" NDES_Validation 3 

        }
        
        else {

            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "MaxRequestBytes set correctly"
            Log-ScriptEvent $LogFilePath "MaxRequestBytes set correctly"  NDES_Validation 1
        
        }

    }

    else {

        Write-Host "IIS is not installed." -BackgroundColor red
        Log-ScriptEvent $LogFilePath "IIS is not installed." NDES_Validation 3

    }

#endregion

#################################################################

#region Checking SPN has been set...

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking SPN has been set..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking SPN has been set" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname

$spn = setspn.exe -L $ADUser

    if ($spn -match $hostname){
    
        Write-Host "Success: " -ForegroundColor Green -NoNewline
        write-host "Correct SPN set for the NDES service account:"
        Write-host
        Write-Host $spn -ForegroundColor Cyan
        Log-ScriptEvent $LogFilePath "Correct SPN set for the NDES service account: $($spn)"  NDES_Validation 1
    
    }
    
    else {

        Write-Host "Error: Missing or Incorrect SPN set for the NDES Service Account!" -BackgroundColor red 
        Write-Host 'Please review "Step 3.1c - Configure prerequisites on the NDES server".'
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "Missing or Incorrect SPN set for the NDES Service Account"  NDES_Validation 3 
    
    }

#endregion

#################################################################

#region Checking there are no intermediate certs are in the Trusted Root store
       
Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking there are no intermediate certs are in the Trusted Root store..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking there are no intermediate certs are in the Trusted Root store" NDES_Validation 1

$IntermediateCertCheck = Get-Childitem cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}

    if ($IntermediateCertCheck){
    
        Write-Host "Error: Intermediate certificate found in the Trusted Root store. This can cause undesired effects and should be removed." -BackgroundColor red 
        Write-Host "Certificates:"
        Write-Host 
        Write-Host $IntermediateCertCheck
        Log-ScriptEvent $LogFilePath "Intermediate certificate found in the Trusted Root store: $($IntermediateCertCheck)"  NDES_Validation 3
    
    }
    
    else {

        Write-Host "Success: " -ForegroundColor Green -NoNewline
        Write-Host "Trusted Root store does not contain any Intermediate certificates."
        Log-ScriptEvent $LogFilePath "Trusted Root store does not contain any Intermediate certificates."  NDES_Validation 1
    
    }

#endregion

#################################################################

#region Checking the EnrollmentAgentOffline and CEPEncryption are present

$ErrorActionPreference = "Silentlycontinue"

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking the EnrollmentAgentOffline and CEPEncryption are present..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking the EnrollmentAgentOffline and CEPEncryption are present" NDES_Validation 1

$certs = Get-ChildItem cert:\LocalMachine\My\

    # Looping through all certificates in LocalMachine Store
    Foreach ($item in $certs){
      
    $Output = ($item.Extensions| where-object {$_.oid.FriendlyName -like "**"}).format(0).split(",")

        if ($Output -match "EnrollmentAgentOffline"){
        
            $EnrollmentAgentOffline = $TRUE
        
        }
            
        if ($Output -match "CEPEncryption"){
            
            $CEPEncryption = $TRUE
            
        }

    } 
    
    # Checking if EnrollmentAgentOffline certificate is present
    if ($EnrollmentAgentOffline){
    
        Write-Host "Success: " -ForegroundColor Green -NoNewline
        Write-Host "EnrollmentAgentOffline certificate is present"
        Log-ScriptEvent $LogFilePath "EnrollmentAgentOffline certificate is present"  NDES_Validation 1
    
    }
    
    else {

        Write-Host "Error: EnrollmentAgentOffline certificate is not present!" -BackgroundColor red 
        Write-Host "This can take place when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions." 
        write-host 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "EnrollmentAgentOffline certificate is not present"  NDES_Validation 3 
    
    }
    
    # Checking if CEPEncryption is present
    if ($CEPEncryption){
        
        Write-Host "Success: " -ForegroundColor Green -NoNewline
        Write-Host "CEPEncryption certificate is present"
        Log-ScriptEvent $LogFilePath "CEPEncryption certificate is present"  NDES_Validation 1
        
    }
        
    else {

        Write-Host "Error: CEPEncryption certificate is not present!" -BackgroundColor red 
        Write-Host "This can take place when an account without Enterprise Admin permissions installs NDES. You may need to remove the NDES role and reinstall with the correct permissions." 
        write-host 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "CEPEncryption certificate is not present"  NDES_Validation 3
        
    }

$ErrorActionPreference = "Continue"

#endregion

#################################################################         

#region Checking registry has been set with the SCEP certificate template name

Write-host
Write-host "......................................................."
Write-host
Write-Host 'Checking registry "HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP" has been set with the SCEP certificate template name...' -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking registry (HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP) has been set with the SCEP certificate template name" NDES_Validation 1

    if (-not (Test-Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP)){

        Write-host "Error: Registry key does not exist. This can occur if the NDES role has been installed but not configured." -BackgroundColor Red
        Write-host 'Please review "Step 3 - Configure prerequisites on the NDES server".'
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "MSCEP Registry key does not exist."  NDES_Validation 3 

    }

    else {

    $SignatureTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name SignatureTemplate).SignatureTemplate
    $EncryptionTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name EncryptionTemplate).EncryptionTemplate
    $GeneralPurposeTemplate = (Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name GeneralPurposeTemplate).GeneralPurposeTemplate 
    $DefaultUsageTemplate = "IPSECIntermediateOffline"

        if ($SignatureTemplate -match $DefaultUsageTemplate -AND $EncryptionTemplate -match $DefaultUsageTemplate -AND $GeneralPurposeTemplate -match $DefaultUsageTemplate){
        
            Write-Host "Error: Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed." -BackgroundColor red
            write-host 'Please review "Step 3.1 - Configure prerequisites on the NDES server".' 
            write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
            Write-Host
            Log-ScriptEvent $LogFilePath "Registry has not been configured with the SCEP Certificate template name. Default values have _not_ been changed."  NDES_Validation 3
            $FurtherReading = $FALSE
        
        }

        else {

            Write-Host "One or more default values have been changed."
            Write-Host 
            write-host "Checking SignatureTemplate key..."
            Write-host
        
            if ($SignatureTemplate -match $SCEPUserCertTemplate){

                Write-Host "Success: " -ForegroundColor Green -NoNewline
                write-host "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template."
                Write-host
                Log-ScriptEvent $LogFilePath "SCEP certificate template $($SCEPUserCertTemplate)' has been written to the registry under the _SignatureTemplate_ key"  NDES_Validation 1

            }

            else {
        
                Write-Warning '"SignatureTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the "Signature" purpose, this can safely be ignored."'
                Write-Host
                write-host "Registry value: " -NoNewline
                Write-host "$($SignatureTemplate)" -ForegroundColor Cyan
                Write-Host
                write-host "SCEP certificate template value: " -NoNewline
                Write-host "$($SCEPUserCertTemplate)" -ForegroundColor Cyan
                Write-Host
                Log-ScriptEvent $LogFilePath "SignatureTemplate key does not match the SCEP certificate template name.Registry value=$($SignatureTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)"  NDES_Validation 2
        
            }
                
                Write-host "......................."
                Write-Host
                Write-Host "Checking EncryptionTemplate key..."
                Write-host

                if ($EncryptionTemplate -match $SCEPUserCertTemplate){
            
                    Write-Host "Success: " -ForegroundColor Green -NoNewline
                    write-host "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _EncryptionTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template."
                    Write-host
                    Log-ScriptEvent $LogFilePath "SCEP certificate template $($SCEPUserCertTemplate) has been written to the registry under the _EncryptionTemplate_ key"  NDES_Validation 1

            
                }
            
                else {

                    Write-Warning '"EncryptionTemplate key does not match the SCEP certificate template name. Unless your template is explicitly set for the "Encryption" purpose, this can safely be ignored."'
                    Write-Host
                    write-host "Registry value: " -NoNewline
                    Write-host "$($EncryptionTemplate)" -ForegroundColor Cyan
                    Write-Host
                    write-host "SCEP certificate template value: " -NoNewline
                    Write-host "$($SCEPUserCertTemplate)" -ForegroundColor Cyan
                    Write-Host
                    Log-ScriptEvent $LogFilePath "EncryptionTemplate key does not match the SCEP certificate template name.Registry value=$($EncryptionTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)"  NDES_Validation 2

            
                }
                
                    Write-host "......................."
                    Write-Host
                    Write-Host "Checking GeneralPurposeTemplate key..."
                    Write-host

                    if ($GeneralPurposeTemplate -match $SCEPUserCertTemplate){
                
                        Write-Host "Success: " -ForegroundColor Green -NoNewline
                        write-host "SCEP certificate template '$($SCEPUserCertTemplate)' has been written to the registry under the _GeneralPurposeTemplate_ key. Ensure this aligns with the usage specificed on the SCEP template"
                        Log-ScriptEvent $LogFilePath "SCEP certificate template $($SCEPUserCertTemplate) has been written to the registry under the _GeneralPurposeTemplate_ key"  NDES_Validation 1

                    }
                
                    else {

                        Write-Warning '"GeneralPurposeTemplate key does not match the SCEP certificate template name. Unless your template is set for the "Signature and Encryption" (General) purpose, this can safely be ignored."'
                        Write-Host
                        write-host "Registry value: " -NoNewline
                        Write-host "$($GeneralPurposeTemplate)" -ForegroundColor Cyan
                        Write-Host
                        write-host "SCEP certificate template value: " -NoNewline
                        Write-host "$($SCEPUserCertTemplate)" -ForegroundColor Cyan
                        Write-Host
                        Log-ScriptEvent $LogFilePath "GeneralPurposeTemplate key does not match the SCEP certificate template name.Registry value=$($GeneralPurposeTemplate)|SCEP certificate template value=$($SCEPUserCertTemplate)"  NDES_Validation 2

                
                    }

        }

        if ($furtherreading-EQ $true){
        
            Write-host "......................."
            Write-Host
            Write-host 'For further reading, please review "Step 4.2 - Configure NDES for use with Intune".'
            write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"

        }

    }
        
$ErrorActionPreference = "Continue"

#endregion

#################################################################

#region Checking server certificate.

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking IIS SSL certificate is valid for use..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking IIS SSL certificate is valid for use" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$serverAuthEKU = "1.3.6.1.5.5.7.3.1" # Server Authentication
$allSSLCerts = Get-ChildItem Cert:\LocalMachine\My
$BoundServerCert = netsh http show sslcert
    
    foreach ($Cert in $allSSLCerts) {       

    $ServerCertThumb = $cert.Thumbprint

        if ($BoundServerCert -match $ServerCertThumb){

            $BoundServerCertThumb = $ServerCertThumb

        }

    }

$ServerCertObject = Get-ChildItem Cert:\LocalMachine\My\$BoundServerCertThumb

    if ($ServerCertObject.Issuer -match $ServerCertObject.Subject){

        $SelfSigned = $true

    }

    else {
    
        $SelfSigned = $false
    
    }

        if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU -AND (($ServerCertObject.Subject -match $hostname) -or ($ServerCertObject.DnsNameList -match $hostname)) -AND $ServerCertObject.Issuer -notmatch $ServerCertObject.Subject){

            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "Certificate bound in IIS is valid:"
            Write-Host
            Write-Host "Subject: " -NoNewline
            Write-host "$($ServerCertObject.Subject)" -ForegroundColor Cyan
            Write-Host
            Write-Host "Thumbprint: " -NoNewline
            Write-Host "$($ServerCertObject.Thumbprint)" -ForegroundColor Cyan
            Write-Host
            Write-Host "Valid Until: " -NoNewline
            Write-Host "$($ServerCertObject.NotAfter)" -ForegroundColor Cyan
            Write-Host
            Write-Host "If this NDES server is in your perimeter network, please ensure the external hostname is shown below:" -ForegroundColor Blue -BackgroundColor White
            $DNSNameList = $ServerCertObject.DNSNameList.unicode
            Write-Host
            write-host "Internal and External hostnames: " -NoNewline
            Write-host "$($DNSNameList)" -ForegroundColor Cyan
            Log-ScriptEvent $LogFilePath "Certificate bound in IIS is valid. Subject:$($ServerCertObject.Subject)|Thumbprint:$($ServerCertObject.Thumbprint)|ValidUntil:$($ServerCertObject.NotAfter)|Internal&ExternalHostnames:$($DNSNameList)" NDES_Validation 1

            }
    
        else {

        Write-Host "Error: The certificate bound in IIS is not valid for use. Reason:" -BackgroundColor red 
        write-host
          

                if ($ServerCertObject.EnhancedKeyUsageList -match $serverAuthEKU) {
                
                    $EKUValid = $true

                }

                else {
                
                    $EKUValid = $false

                    write-host "Correct EKU: " -NoNewline
                    Write-Host "$($EKUValid)" -ForegroundColor Cyan
                    Write-Host
                
                }

                if ($ServerCertObject.Subject -match $hostname) {
                
                    $SubjectValid = $true

                }

                else {
                
                    $SubjectValid = $false

                    write-host "Correct Subject: " -NoNewline
                    write-host "$($SubjectValid)" -ForegroundColor Cyan
                    Write-Host
                
                }

                if ($SelfSigned -eq $false){
               
                    Out-Null
                
                }

                else {
                
                    write-host "Is Self-Signed: " -NoNewline
                    write-host "$($SelfSigned)" -ForegroundColor Cyan
                    Write-Host
                
                }

        Write-Host 'Please review "Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server".'
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "The certificate bound in IIS is not valid for use. CorrectEKU=$($EKUValid)|CorrectSubject=$($SubjectValid)|IsSelfSigned=$($SelfSigned)"  NDES_Validation 3

}
        
#endregion

#################################################################

#region Checking Client certificate.

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking Client certificate (NDES Policy module) is valid for use..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking Client certificate (NDES Policy module) is valid for use" NDES_Validation 1

$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
$clientAuthEku = "1.3.6.1.5.5.7.3.2" # Client Authentication
$NDESCertThumbprint = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\Modules\NDESPolicy -Name NDESCertThumbprint).NDESCertThumbprint
$ClientCertObject = Get-ChildItem Cert:\LocalMachine\My\$NDESCertThumbprint

    if ($ClientCertObject.Issuer -match $ClientCertObject.Subject){

        $ClientCertSelfSigned = $true

    }

    else {
    
        $ClientCertSelfSigned = $false
    
    }

        if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku -AND $ClientCertObject.Subject -match $hostname -AND $ClientCertObject.Issuer -notmatch $ClientCertObject.Subject){

            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "Client certificate bound to NDES Connector is valid:"
            Write-Host
            Write-Host "Subject: " -NoNewline
            Write-host "$($ClientCertObject.Subject)" -ForegroundColor Cyan
            Write-Host
            Write-Host "Thumbprint: " -NoNewline
            Write-Host "$($ClientCertObject.Thumbprint)" -ForegroundColor Cyan
            Write-Host
            Write-Host "Valid Until: " -NoNewline
            Write-Host "$($ClientCertObject.NotAfter)" -ForegroundColor Cyan
            Log-ScriptEvent $LogFilePath "Client certificate bound to NDES Connector is valid. Subject:$($ClientCertObject.Subject)|Thumbprint:$($ClientCertObject.Thumbprint)|ValidUntil:$($ClientCertObject.NotAfter)"  NDES_Validation 1

        }
    
        else {

        Write-Host "Error: The certificate bound to the NDES Connector is not valid for use. Reason:" -BackgroundColor red 
        write-host  

                if ($ClientCertObject.EnhancedKeyUsageList -match $clientAuthEku) {
                
                    $ClientCertEKUValid = $true

                }

                else {
                
                    $ClientCertEKUValid = $false

                    write-host "Correct EKU: " -NoNewline
                    Write-Host "$($ClientCertEKUValid)" -ForegroundColor Cyan
                    Write-Host
                
                }

                if ($ClientCertObject.Subject -match $hostname) {
                
                    $ClientCertSubjectValid = $true

                }

                else {
                
                    $ClientCertSubjectValid = $false

                    write-host "Correct Subject: " -NoNewline
                    write-host "$($ClientCertSubjectValid)" -ForegroundColor Cyan
                    Write-Host
                
                }

                if ($ClientCertSelfSigned -eq $false){
               
                    Out-Null
                
                }

                else {
                
                    write-host "Is Self-Signed: " -NoNewline
                    write-host "$($ClientCertSelfSigned)" -ForegroundColor Cyan
                    Write-Host
                
                }

        Write-Host 'Please review "Step 4 - Configure NDES for use with Intune>To Install and bind certificates on the NDES Server".'
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Log-ScriptEvent $LogFilePath "The certificate bound to the NDES Connector is not valid for use. CorrectEKU=$($ClientCertEKUValid)|CorrectSubject=$($ClientCertSubjectValid)|IsSelfSigned=$($ClientCertSelfSigned)"  NDES_Validation 3


}
        
#endregion

#################################################################

#region Checking behaviour of internal NDES URL

Write-host
Write-host "......................................................."
$hostname = ([System.Net.Dns]::GetHostByName(($env:computerName))).hostname
Write-host
Write-Host "Checking behaviour of internal NDES URL: " -NoNewline -ForegroundColor Yellow
Write-Host "https://$hostname/certsrv/mscep/mscep.dll" -ForegroundColor Cyan
Write-host
Log-ScriptEvent $LogFilePath "Checking behaviour of internal NDES URL" NDES_Validation 1
Log-ScriptEvent $LogFilePath "Https://$hostname/certsrv/mscep/mscep.dll" NDES_Validation 1

$Statuscode = try {(Invoke-WebRequest -Uri https://$hostname/certsrv/mscep/mscep.dll).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

    if ($statuscode -eq "200"){

    Write-host "Error: https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or not being installed." -BackgroundColor Red
    Log-ScriptEvent $LogFilePath "https://$hostname/certsrv/mscep/mscep.dll returns 200 OK. This usually signifies an error with the Intune Connector registering itself or not being installed"  NDES_Validation 3
    } 

    elseif ($statuscode -eq "403"){

    Write-Host "Trying to retrieve CA Capabilitiess..." -ForegroundColor Yellow
    Write-Host
    $Newstatuscode = try {(Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep/mscep.dll?operation=GetCACaps&message=test").statuscode} catch {$_.Exception.Response.StatusCode.Value__}

        if ($Newstatuscode -eq "200"){

        $CACaps = (Invoke-WebRequest -Uri "https://$hostname/certsrv/mscep?operation=GetCACaps&message=test").content

        }

            if ($CACaps){

            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "CA Capabilities retrieved:"
            Write-Host
            write-host $CACaps
            Log-ScriptEvent $LogFilePath "CA Capabilities retrieved:$CACaps"  NDES_Validation 1
                
            }

    }
                    
    else {
    
        Write-host "Error: Unexpected Error code! This usually signifies an error with the Intune Connector registering itself or not being installed" -BackgroundColor Red
        Write-host "Expected value is a 403. We received a $($Statuscode). This could be down to a missing reboot post policy module install. Verify last boot time and module install time further down the validation."
        Log-ScriptEvent $LogFilePath "Unexpected Error code. Expected:403|Received:$Statuscode"  NDES_Validation 3
    
   }
        
#endregion

#################################################################

#region Checking Servers last boot time

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking Servers last boot time..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking Servers last boot time" NDES_Validation 1

$LastBoot = (Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime'
;EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).lastbootuptime

write-host "Server last rebooted: "-NoNewline
Write-Host "$($LastBoot). " -ForegroundColor Cyan -NoNewline
Write-Host "Please ensure a reboot has taken place _after_ all registry changes and installing the NDES Connector. IISRESET is _not_ sufficient."
Log-ScriptEvent $LogFilePath "LastBootTime:$LastBoot"  NDES_Validation 1

#endregion

#################################################################

#region Checking Intune Connector is installed

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking Intune Connector is installed..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking Intune Connector is installed" NDES_Validation 1 

    if ($IntuneConnector = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ? {$_.DisplayName -eq "Microsoft Intune Connector"}){

        Write-Host "Success: " -ForegroundColor Green -NoNewline
        Write-Host "$($IntuneConnector.DisplayName) was installed on " -NoNewline 
        Write-Host "$($IntuneConnector.InstallDate) " -ForegroundColor Cyan -NoNewline 
        write-host "and is version " -NoNewline
        Write-Host "$($IntuneConnector.DisplayVersion)" -ForegroundColor Cyan -NoNewline
        Write-host
        Log-ScriptEvent $LogFilePath "ConnectorVersion:$IntuneConnector"  NDES_Validation 1

    }

    else {

        Write-Host "Error: Intune Connector not installed" -BackgroundColor red 
        Write-Host 'Please review "Step 5 - Enable, install, and configure the Intune certificate connector".'
        write-host "URL: https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure"
        Write-Host
        Log-ScriptEvent $LogFilePath "ConnectorNotInstalled"  NDES_Validation 3 
        
    }


#endregion

#################################################################

#region Checking Intune Connector registry keys (KeyRecoveryAgentCertificate, PfxSigningCertificate and SigningCertificate)

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking Intune Connector registry keys are intact" -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking Intune Connector registry keys are intact" NDES_Validation 1
$ErrorActionPreference = "SilentlyContinue"

$KeyRecoveryAgentCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\KeyRecoveryAgentCertificate"
$PfxSigningCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\PfxSigningCertificate"
$SigningCertificate = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\SigningCertificate"

    if (-not ($KeyRecoveryAgentCertificate)){

        Write-host "Error: KeyRecoveryAgentCertificate Registry key does not exist." -BackgroundColor Red
        Write-Host
        Log-ScriptEvent $LogFilePath "KeyRecoveryAgentCertificate Registry key does not exist."  NDES_Validation 3 

    }

        else {

        $KeyRecoveryAgentCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name KeyRecoveryAgentCertificate).KeyRecoveryAgentCertificate

            if (-not ($KeyRecoveryAgentCertificatePresent)) {
    
                Write-Warning "KeyRecoveryAgentCertificate registry key exists but has no value"
                Log-ScriptEvent $LogFilePath "KeyRecoveryAgentCertificate missing Value"  NDES_Validation 2

            }

            else {
    
                Write-Host "Success: " -ForegroundColor Green -NoNewline
                Write-Host "KeyRecoveryAgentCertificate registry key exists"
                Log-ScriptEvent $LogFilePath "KeyRecoveryAgentCertificate registry key exists"  NDES_Validation 1

            }



    }

    if (-not ($PfxSigningCertificate)){

        Write-host "Error: PfxSigningCertificate Registry key does not exist." -BackgroundColor Red
        Write-Host
        Log-ScriptEvent $LogFilePath "PfxSigningCertificate Registry key does not exist."  NDES_Validation 3 


        }

        else {

        $PfxSigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name PfxSigningCertificate).PfxSigningCertificate

            if (-not ($PfxSigningCertificatePresent)) {
    
                Write-Warning "PfxSigningCertificate registry key exists but has no value"
                Log-ScriptEvent $LogFilePath "PfxSigningCertificate missing Value"  NDES_Validation 2

            }

            else {
    
                Write-Host "Success: " -ForegroundColor Green -NoNewline
                Write-Host "PfxSigningCertificate registry keys exists"
                Log-ScriptEvent $LogFilePath "PfxSigningCertificate registry key exists"  NDES_Validation 1

        }



    }

    if (-not ($SigningCertificate)){

        Write-host "Error: SigningCertificate Registry key does not exist." -BackgroundColor Red
        Write-Host
        Log-ScriptEvent $LogFilePath "SigningCertificate Registry key does not exist"  NDES_Validation 3  

    }

        else {

        $SigningCertificatePresent = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\NDESConnector\ -Name SigningCertificate).SigningCertificate

            if (-not ($SigningCertificatePresent)) {
    
                Write-Warning "SigningCertificate registry key exists but has no value"
                Log-ScriptEvent $LogFilePath "SigningCertificate registry key exists but has no value"  NDES_Validation 2


            }

            else {
    
                Write-Host "Success: " -ForegroundColor Green -NoNewline
                Write-Host "SigningCertificate registry key exists"
                Log-ScriptEvent $LogFilePath "SigningCertificate registry key exists"  NDES_Validation 1


            }



    }

$ErrorActionPreference = "Continue"

#endregion

#################################################################

#region Checking eventlog for pertinent errors

$ErrorActionPreference = "SilentlyContinue"
$EventLogCollDays = ((Get-Date).AddDays(-5)) #Number of days to go back in the event log

Write-host
Write-host "......................................................."
Write-host
Write-Host "Checking Event logs for pertinent errors..." -ForegroundColor Yellow
Write-host
Log-ScriptEvent $LogFilePath "Checking Event logs for pertinent errors" NDES_Validation 1

    if (-not (Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After $EventLogCollDays -ErrorAction silentlycontinue)) {

        Write-Host "Success: " -ForegroundColor Green -NoNewline
        write-host "No errors found in the Microsoft Intune Connector"
        Write-host
        Log-ScriptEvent $LogFilePath "No errors found in the Microsoft Intune Connector"  NDES_Validation 1

    }

    else {

        Write-Warning "Errors found in the Microsoft Intune Connector Event log. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Host
        $EventsCol1 = (Get-EventLog -LogName "Microsoft Intune Connector" -EntryType Error -After $EventLogCollDays -Newest 5 | select TimeGenerated,Source,Message)
        $EventsCol1 | fl
        Log-ScriptEvent $LogFilePath "Errors found in the Microsoft Intune Connector Event log"  NDES_Eventvwr 3
        $i = 0
        $count = @($EventsCol1).count

        foreach ($item in $EventsCol1) {

            Log-ScriptEvent $LogFilePath "$($EventsCol1[$i].TimeGenerated);$($EventsCol1[$i].Message);$($EventsCol1[$i].Source)"  NDES_Eventvwr 3
            $i++

            }
            
        }

            if (-not (Get-EventLog -LogName "Application" -EntryType Error -Source NDESConnector,Microsoft-Windows-NetworkDeviceEnrollmentService -After $EventLogCollDays -ErrorAction silentlycontinue)) {

            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"
            Write-host
            Log-ScriptEvent $LogFilePath "No errors found in the Application log from source NetworkDeviceEnrollmentService or NDESConnector"  NDES_Validation 1

            }

    else {

        Write-Warning "Errors found in the Application Event log for source NetworkDeviceEnrollmentService or NDESConnector. Please see below for the most recent 5, and investigate further in Event Viewer."
        Write-Host
        $EventsCol2 = (Get-EventLog -LogName "Application" -EntryType Error -Source NDESConnector,Microsoft-Windows-NetworkDeviceEnrollmentService -After $EventLogCollDays -Newest 5 | select TimeGenerated,Source,Message)
        $EventsCol2 |fl
        $i = 0
        $count = @($EventsCol2).count

        foreach ($item in $EventsCol2) {

            Log-ScriptEvent $LogFilePath "$($EventsCol2[$i].TimeGenerated);$($EventsCol2[$i].Message);$($EventsCol2[$i].Source)"  NDES_Eventvwr 3
            $i++

    }

}

$ErrorActionPreference = "Continue"

#endregion

#################################################################

#region Zip up logfiles

Write-host
Write-host "......................................................."
Write-host
Write-host "Log Files..." -ForegroundColor Yellow
Write-host 
write-host "Do you want to gather troubleshooting files? This includes IIS, NDES Connector, NDES Plugin, CRP, and MSCEP log files, in addition to the SCEP template configuration.  [Y]es, [N]o:"
$LogFileCollectionConfirmation = Read-Host

    if ($LogFileCollectionConfirmation -eq "y"){

    $IISLogPath = (Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory).Value + "\W3SVC1" -replace "%SystemDrive%",$env:SystemDrive
    $IISLogs = Get-ChildItem $IISLogPath| Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $NDESConnectorLogs = Get-ChildItem "C:\Program Files\Microsoft Intune\NDESConnectorSvc\Logs\Logs\NDESConnector*" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $NDESPluginLogs = Get-ChildItem "C:\Program Files\Microsoft Intune\NDESPolicyModule\Logs\NDESPlugin.log"
    $MSCEPLogs = Get-ChildItem "c:\users\*\mscep.log" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3
    $CRPLogs = Get-ChildItem "C:\Program Files\Microsoft Intune\NDESConnectorSvc\Logs\Logs\CertificateRegistrationPoint*" | Sort-Object -Descending -Property LastWriteTime | Select-Object -First 3

    foreach ($IISLog in $IISLogs){

    Copy-Item -Path $IISLog.FullName -Destination $TempDirPath

    }

    foreach ($NDESConnectorLog in $NDESConnectorLogs){

    Copy-Item -Path $NDESConnectorLog.FullName -Destination $TempDirPath

    }

    foreach ($NDESPluginLog in $NDESPluginLogs){

    Copy-Item -Path $NDESPluginLog.FullName -Destination $TempDirPath

    }

    foreach ($MSCEPLog in $MSCEPLogs){

    Copy-Item -Path $MSCEPLog.FullName -Destination $TempDirPath

    }

    foreach ($CRPLog in $CRPLogs){

    Copy-Item -Path $CRPLogs.FullName -Destination $TempDirPath

    }

    $SCEPUserCertTemplateOutputFilePath = "$($TempDirPath)\SCEPUserCertTemplate.txt"
    certutil -v -template $SCEPUserCertTemplate > $SCEPUserCertTemplateOutputFilePath

    Log-ScriptEvent $LogFilePath "Collecting server logs"  NDES_Validation 1

    Add-Type -assembly "system.io.compression.filesystem"
    $Currentlocation =  $env:temp
    $date = Get-Date -Format ddMMyyhhmm
    [io.compression.zipfile]::CreateFromDirectory($TempDirPath, "$($Currentlocation)\$($date)-Logs-$($hostname).zip")

    Write-host
    Write-Host "Success: " -ForegroundColor Green -NoNewline
    write-host "Log files copied to $($Currentlocation)\$($date)-Logs-$($hostname).zip"
    Write-host

    }

    else {

    Log-ScriptEvent $LogFilePath "Do not collect logs"  NDES_Validation 1
    $WriteLogOutputPath = $True

    }


#endregion

#################################################################

#region Ending script

Write-host
Write-host "......................................................."
Write-host
Write-host "End of NDES configuration validation" -ForegroundColor Yellow
Write-Host

    if ($WriteLogOutputPath -eq $True) {

        write-host "Log file copied to $($LogFilePath)"
        Write-Host

    }
write-host "Ending script..." -ForegroundColor Yellow
Write-host 

#endregion

#################################################################

}

else {

Write-Host
Write-host "......................................................."
Write-Host
Write-host "Incorrect variables. Please run the script again..." -ForegroundColor Red
Write-Host
Write-Host "Exiting................................................"
Write-Host
exit

}
