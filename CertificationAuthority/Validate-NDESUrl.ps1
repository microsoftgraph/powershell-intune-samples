<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

.SYNOPSIS
Validate-NDESUrl will check that requests from devices enrolled in Microsoft Intune will get through all the network protections (such as a reverse proxy) and make it to the NDES server.

.DESCRIPTION
Validate-NDESUrl.ps1 will ensure requests from devices enrolled in Microsoft Intune and targeted with a SCEP policy will successfully traverse the network path to the NDES server. Since the certificate request includes a query string that is longer than what is allowed by the default settings in Windows IIS and some reverse proxy servers, those servers and network devices must be configured to allow long query strings and web requests.
This tool will simulate a SCEP request with a large payload, enabling you to check the IIS logs on the NDES server to ensure that the request is not being blocked anywhere along the path.
A query size of 30 is suggested as a starting point – success with this size suggests a valid configuration through the network path.

.EXAMPLE
.\Validate-NDESUrl.ps1 -server externalDNSName.contoso.com -querysize 30
.EXAMPLE
.\Validate-NDESUrl.ps1 -help

#>

[CmdletBinding(DefaultParameterSetName="NormalRun")]
Param(
  
    [parameter(Mandatory=$true,ParameterSetName="NormalRun")]
    [alias("s")]
    [string]$server,

    [parameter(Mandatory=$true,ParameterSetName="NormalRun")]
    [alias("q")]
    [ValidateRange(1,31)] 
    [INT]$querysize,

    [parameter(ParameterSetName="Help")]
    [alias("h","?","/?")]
    [switch]$help,
    
    [parameter(ParameterSetName="Help")]
    [alias("u")]
    [switch]$usage
    )

function Show-Usage
{
    Write-Host
    Write-Host "-help                       -h         Displays the help."
    Write-Host "-usage                      -u         Displays this usage information."
    Write-Host "-querysize                  -q         Specify the size of the query string payload to use as a number of kilobytes (i.e. 20 or 25). Maximum value is 31"
    Write-Host "-server                     -s         Specify NDES server public DNS name in the form FQDN. For example ExternalDNSName.Contoso.com"
    Write-Host
}

#################################################################

function Get-NDESURLHelp(){

    write-host "Validate-NDESUrl.ps1 will ensure requests from devices enrolled in Microsoft Intune and targeted with a SCEP policy will successfully traverse the network path to the NDES server."
    write-host "Since the certificate request includes a query string that is longer than what is allowed by the default settings in Windows IIS and some reverse proxy servers, those servers and network devices must be configured to allow long query strings and web requests."
    Write-Host
    write-host "This tool will simulate a SCEP request with a large payload, enabling you to check the IIS logs on the NDES server to ensure that the request is not being blocked anywhere along the path."
    Write-Host
}

    if ($help){

        Get-NDESURLHelp
        break

    }

    if ($usage){
        
        Show-Usage 
        break
    }

#Requires -version 4.0
#Requires -RunAsAdministrator

#################################################################

#region Configuring base URI and ensuring it is in a fit state to proceed
 
Write-host
Write-host "......................................................."
Write-host
Write-Host "Trying base NDES URI... " -ForegroundColor Yellow
Write-host
 
    if (Resolve-DnsName $server -ErrorAction SilentlyContinue){

    $NDESUrl = "https://$($server)/certsrv/mscep/mscep.dll"
    $BaseURLstatuscode = try {(Invoke-WebRequest -Uri $NDESUrl).statuscode} catch {$_.Exception.Response.StatusCode.Value__}
 
        if ($BaseURLstatuscode -eq "200"){
 
            Write-Warning "$($NDESUrl) returns a status code 200. This may signify an error with the Intune Certificate Connector registering itself or not being installed."
            Write-Host
            Write-Host "This state will _not_ provide a working NDES infrastructure, although validation of long URI support will continue."
            Write-Host
    
        }
 
        elseif ($BaseURLstatuscode -eq "403"){
 
            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "Proceeding with validation!"
 
        }
 
        else {
    
            Write-Warning "Unexpected Error code! This may signify an error with the Intune Certificate Connector registering itself or not being installed."
            Write-Host
            Write-host "Expected value is a 403. We received a $($BaseURLstatuscode). This state will _not_ provide a working NDES infrastructure, although validation of long URI support will continue."
    
        }
 
    }
 
    else {
    
        write-host "Error: Cannot resolve $($server)" -BackgroundColor Red
        Write-Host
        Write-Host "Please ensure a DNS record is in place and name resolution is successful"
        Write-Host
        Write-Host "Exiting..."
        Write-Host
        exit
    
    }

#endregion

#################################################################

#region Trying to retrieve CA Certificates

Write-host
Write-host "......................................................."
Write-host
Write-Host "Trying to retrieve CA Certificates... " -ForegroundColor Yellow
Write-host
$GetCACerts = "$($NDESUrl)?operation=GetCACerts&message=NDESLongUrlValidatorStep2of3"
$CACertsStatuscode = try {(Invoke-WebRequest -Uri $GetCACerts).statuscode} catch {$_.Exception.Response.StatusCode.Value__}

    if (-not ($CACertsStatuscode -eq "200")){

        Write-host "Attempting to retrieve certificates from the following URI: " -NoNewline
        Write-Host "$GetCACerts" -ForegroundColor Cyan
        Write-host
        write-host "Error: Server returned a $CACertsStatuscode error. " -BackgroundColor Red
        Write-Host
        write-host "For a list of IIS error codes, please visit the below link."
        Write-Host "URL: https://support.microsoft.com/en-gb/help/943891/the-http-status-code-in-iis-7-0--iis-7-5--and-iis-8-0"

    }

    else {

    Write-host "Attempting to retrieve certificates from the following URI: " -NoNewline
    Write-Host "$GetCACerts" -ForegroundColor Cyan
    Write-Host

    $CACerts = (Invoke-WebRequest -Uri $GetCACerts).content

        if ($CACerts) {

            Invoke-WebRequest -Uri $GetCACerts -ContentType "application/x-x509-ca-ra-cert" -OutFile "$env:temp\$server.p7b"
            Write-Host "Success: " -ForegroundColor Green -NoNewline
            write-host "certificates retrieved."
            write-host "File written to disk: '$env:temp\$server.p7b'"

        }

        else {

            write-host "Error: Server is not returning CA certificates." -BackgroundColor Red
            Write-Host
            write-host "PLEASE NOTE: This is _not_ a long URI issue. Please investigate the NDES configuration."
            Write-Host

        }

}

#endregion

#################################################################

#region SCEP Challenge

Write-host
Write-host "......................................................."
Write-host
Write-Host "Querying URI with simulated SCEP challenge... " -ForegroundColor Yellow
Write-host

$ChallengeUrlTemp = "$($NDESUrl)?operation=PKIOperation&message=<SCEP CHALLENGE STRING>"

Write-host "Retrieving the following URI: " -NoNewline
Write-Host "$ChallengeUrlTemp" -ForegroundColor Cyan
Write-host
Write-Host "Using a query size of $($querysize)KB... "
Write-Host

$challengeBase = "NDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallengeNDESLongUrlValidatorFakeChallenge";
            
            for ($i=1; $i -le $querySize; $i++){         

                $testChallenge += $challengeBase + ($i + 1)

            }

$LongUrl = "$($NDESUrl)?operation=PKIOperation&message=$($testChallenge)"
$LongUrlStatusCode = try {(Invoke-WebRequest -Uri $LongUrl).statuscode} catch {$_.Exception.Response.StatusCode.Value__} 

    if ($LongUrlStatusCode -eq "414"){

        write-host "Error: HTTP Error 414. The $($querysize)KB URI is too long. " -BackgroundColor Red
        Write-Host
        Write-Host "Please ensure all servers and network devices support long URI's" -ForegroundColor Blue
        write-host

    }

    elseif (-not ($LongUrlStatusCode -eq "200")){

        write-host "Error: HTTP Error $($LongUrlStatusCode)" -BackgroundColor Red
        Write-Host
        Write-Host "Please check your network configuration." -ForegroundColor Blue -BackgroundColor white
        write-host
        write-host "For a list of IIS error codes, please visit the below link."
        Write-Host "URL: https://support.microsoft.com/en-gb/help/943891/the-http-status-code-in-iis-7-0--iis-7-5--and-iis-8-0"

    }

    else {

        Write-Host "Success: " -ForegroundColor Green -NoNewline
        write-host "Server accepts a $($querysize)KB URI."

    }

#endregion

#################################################################

#region Ending script

Write-host
Write-host "......................................................."
Write-host
Write-host "End of NDES URI validation" -ForegroundColor Yellow
Write-Host
write-host "Ending script..." -ForegroundColor Yellow
Write-host 

#endregion