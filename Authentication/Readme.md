# Intune Authentication script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. Auth_From_File.ps1
This script demonstrates how to store a password as a secure string in a file.  The file's contents are used during authentication to supply the password, rather than requiring an interactive user login.

The Authentication region defines two variables:  $User and $Password.  The $User variable indicates the user principal name for the credentials, and the $Password variable indicates the location of the file which has the password string (the password file).

You must change these values prior to running the script.

#### Creating the password file

To create a password file, run the following command from within a PowerShell prompt:

```
Read-Host -Prompt "Enter your tenant password" -AsSecureString | ConvertFrom-SecureString | Out-File "c:\temp\IntuneExport\credentials.txt"
```
In this example, the c:\credentials\credentials.txt file contains a secure string that was generated from the entered password.  That file is used by the Auth_From_File.ps1 as the password.

##### Note:
The password file that is generated is only valid for use in the authentication PowerShell script on the computer that was used to generate the file.  It cannot be transferred or used on any other computer.  

As with any security-related script, ensure that you review the code and the code behavior with your company's security department or security representative to ensure it complies with your security policy.

#### Get-AuthToken Function
This function is used to authenticate with the Microsoft Graph API REST interface. It has been updated to add the following:

```
if($Password -eq $null){

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

}

else {

    if(test-path "$Password"){

    $UserPassword = get-Content "$Password" | ConvertTo-SecureString

    $userCredentials = new-object Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential -ArgumentList $userUPN,$UserPassword

    $authResult = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($authContext, $resourceAppIdURI, $clientid, $userCredentials).Result;

    }

    else {

    Write-Host "Path to Password file" $Password "doesn't exist, please specify a valid path..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break

    }

}
```

#### Region Authentication
Within the Authentication region there are two variables that are used to pass to the Get-AuthToken function. These need to be changed to represent your environment.

```
$User = "serviceaccount@tenant.onmicrosoft.com"
$Password = "c:\credentials\credentials.txt"
```
Once these have been configured to your environment the Get-AuthToken function supports passing the -User and -Password parameter.

```
$global:authToken = Get-AuthToken -User $User -Password "$Password"
```
Note: There are two occurrences of the $global:authToken in the Authentication region.
