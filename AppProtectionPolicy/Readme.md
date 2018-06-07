# Intune App Protection Policy script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. ManagedAppPolicy_Add.ps1
This script adds an App Protection policy into the Intune Service that you have authenticated with. The policies created by the script are shown below in the Android and iOS JSON sections below.

#### Add-ManagedAppPolicy Function
This function is used to add an App Protection policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-ManagedAppPolicy -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-ManagedAppPolicy function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON files are shown below:

#### Android JSON

```JSON
{
  "@odata.type": "#microsoft.graph.androidManagedAppProtection",
  "displayName": "Graph MAM Android Policy",
  "description": "Graph MAM Android Policy",
  "periodOfflineBeforeAccessCheck": "PT12H",
  "periodOnlineBeforeAccessCheck": "PT30M",
  "allowedInboundDataTransferSources": "allApps",
  "allowedOutboundDataTransferDestinations": "allApps",
  "organizationalCredentialsRequired": false,
  "allowedOutboundClipboardSharingLevel": "allApps",
  "dataBackupBlocked": true,
  "deviceComplianceRequired": true,
  "managedBrowserToOpenLinksRequired": true,
  "saveAsBlocked": true,
  "periodOfflineBeforeWipeIsEnforced": "P90D",
  "pinRequired": true,
  "maximumPinRetries": 5,
  "simplePinBlocked": true,
  "minimumPinLength": 4,
  "pinCharacterSet": "numeric",
  "allowedDataStorageLocations": [],
  "contactSyncBlocked": true,
  "printBlocked": true,
  "fingerprintBlocked": true,
  "appDataEncryptionType": "afterDeviceRestart",

  "apps": [
    {
        "mobileAppIdentifier": {
        "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
        "packageId": "com.microsoft.office.outlook"
        }
    },
    {
        "mobileAppIdentifier": {
        "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
        "packageId": "com.microsoft.office.excel"
        }
    }

    ]
}
```
#### iOS JSON

```JSON
{
  "@odata.type": "#microsoft.graph.iosManagedAppProtection",
  "displayName": "Test Graph MAM iOS Policy",
  "description": "Test Graph MAM iOS Policy",
  "periodOfflineBeforeAccessCheck": "PT12H",
  "periodOnlineBeforeAccessCheck": "PT30M",
  "allowedInboundDataTransferSources": "allApps",
  "allowedOutboundDataTransferDestinations": "allApps",
  "organizationalCredentialsRequired": false,
  "allowedOutboundClipboardSharingLevel": "allApps",
  "dataBackupBlocked": true,
  "deviceComplianceRequired": true,
  "managedBrowserToOpenLinksRequired": true,
  "saveAsBlocked": true,
  "periodOfflineBeforeWipeIsEnforced": "P90D",
  "pinRequired": true,
  "maximumPinRetries": 5,
  "simplePinBlocked": true,
  "minimumPinLength": 4,
  "pinCharacterSet": "numeric",
  "allowedDataStorageLocations": [],
  "contactSyncBlocked": true,
  "printBlocked": true,
  "fingerprintBlocked": true,
  "appDataEncryptionType": "afterDeviceRestart",

  "apps": [
    {
        "mobileAppIdentifier": {
        "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
        "bundleId": "com.microsoft.office.outlook"
        }
    },
    {
        "mobileAppIdentifier": {
        "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
        "bundleId": "com.microsoft.office.excel"
        }
    }

    ]
}
```
### 2. ManagedAppPolicy_Add_Assign.ps1
This script adds and Assigns an App Protection policy to an AAD Group into the Intune Service that you have authenticated with. The policies created by the script are shown below in the Android and iOS JSON sections below.

#### Add-ManagedAppPolicy Function
This function is used to add an App Protection policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-ManagedAppPolicy -JSON $JSON
```
#### Assign-ManagedAppPolicy Function
This function is used to assign an App Protection Policy to an AAD Group. There are three required parameters.

+ ID - The ID of the App Protection policy configured in the Intune Service
+ TargetGroupId - The ID of the AAD Group where you want to assign the policy
+ OS - The operating system of the policy your applying. There are two choices here, Android or iOS.

```PowerShell
Assign-ManagedAppPolicy -Id $MAM_PolicyID -TargetGroupId $TargetGroupId -OS iOS
```
#### Get-AADGroup Function
This function is used to get an AAD Group by -GroupName to be used to assign a policy to.

```PowerShell
$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where the policy will be assigned"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }
```

### 3. ManagedAppPolicy_Get.ps1
This script gets all the App Protection policies from the Intune Service that you have authenticated with.

#### Get-ManagedAppPolicy Function
This function is used to get all App Protection policies from the Intune Service.

It supports a single parameter as an input to the function to pull data from the service.

```PowerShell
# Returns all App Protection policies configured in Intune
Get-ManagedAppPolicy

# Returns an App Protection policy that contains the Name configured in Intune
Get-ManagedAppPolicy -Name "Android"

```
### 4. ManagedAppPolicy_MobileAppIdentifier_Get.ps1
This script gets all the App Protection policy Managed Applications from the Intune Service that you have authenticated with.

#### Get-IntuneMAMApplication Function
This function is used to get all App Protection policy Managed Applications from the Intune Service.

It supports multiple parameters as an input to the function to pull data from the service.

```PowerShell
# Returns all MAM / APP applications configured in Intune
Get-IntuneMAMApplication

# Returns all Android MAM / APP applications configured in Intune
Get-IntuneMAMApplication -Android

# Returns all iOS MAM / APP applications configured in Intune
Get-IntuneMAMApplication -iOS
```

### 5. ManagedAppPolicy_Remove.ps1
This script removes an App Protection policy configured in the Intune Service that you have authenticated with.

#### Remove-ManagedAppPolicy Function
This function is used to remove a App Protection policy from the Intune Service.

It supports a single parameter -id as an input to the function to specify the id of the App Protection policy that you wish to remove. The script will get a policy of choice via the -Name parameter and then remove it if it's valid.

```PowerShell
# Removes an individual App Protection policy from the Intune Service
$MAM = Get-ManagedAppPolicy -Name "Test Policy"

Remove-ManagedAppPolicy -id $MAM.id
```
### 6. ManagedAppPolicy_Wipe.ps1
This script wipes a users application data where an App Protection policy has been applied. It will prompt the administrator to confirm wipe of the application data and if there are more than one device associated to the user that has an App Protection Policy application applied, the script will show a menu system of devices.

This script uses the following function to complete the wipe action.

#### Get-AADUser - Function
This function is used to get users from the Azure Active Directory. It supports multiple parameters to get specific data about the user.

```PowerShell
# Gets all users in AAD
Get-AADUser

# Gets a specific user by user Principle Name
Get-AADUser -userPrincipalName "user@tenant.onmicrosoft.com"

# Gets a specific user property from AAD
Get-AADUser -userPrincipalName "user@tenant.onmicrosoft.com" -Property MemberOf
```

#### Get-AADUserManagedAppRegistrations Function
This function is used to get an App Protection application registrations found for the user. It has a mandatory parameter of -id for the users AAD ID.
```PowerShell
Get-AADUserManagedAppRegistrations -id $UserID
```

### 7. ManagedAppPolicy_Export.ps1
This script gets all App Protection policies (Android and iOS) from the Intune Service that you have authenticated with. The script will then export the policy to .json format in the directory of your choice.

```PowerShell
$ExportPath = Read-Host -Prompt "Please specify a path to export the policy data to e.g. C:\IntuneOutput"

    # If the directory path doesn't exist prompt user to create the directory

    if(!(Test-Path "$ExportPath")){

    Write-Host
    Write-Host "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow

    $Confirm = read-host

        if($Confirm -eq "y" -or $Confirm -eq "Y"){

        new-item -ItemType Directory -Path "$ExportPath" | Out-Null
        Write-Host

        }

        else {

        Write-Host "Creation of directory path was cancelled..." -ForegroundColor Red
        Write-Host
        break

        }

    }
```

#### Get-ManagedAppPolicy Function
This function is used to get all App Protection Policies from the Intune Service.

It supports a single parameter as an input to the function to pull data from the service.

```PowerShell
# Returns all App Protection policies configured in Intune
Get-ManagedAppPolicy

# Returns an App Protection policy that contains the Name configured in Intune
Get-ManagedAppPolicy -Name "Android"

```

#### Get-ManagedAppProtection Function
This function is used to get managed app protection configuration from the Intune Service.

It supports multiple parameters as an input to the function to pull specific data from the service.

```PowerShell
# Returns a managed app protection policy for Android configured in Intune
Get-ManagedAppProtection -id $id -OS "Android"

# Returns a managed app protection policy for iOS configured in Intune
Get-ManagedAppProtection -id $id -OS "iOS"

# Returns a managed app protection policy for Windows 10 without enrollment configured in Intune
Get-ManagedAppProtection -id $id -OS "WIP_WE"
```

#### Export-JSONData Function
This function is used to export the policy information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```

### 8. ManagedAppPolicy_Import_FromJSON.ps1
This script imports from a JSON file an App Protection Policy into the Intune Service that you have authenticated with.

When you run the script it will prompt for a path to a .json file, if the path is valid the Add-ManagedAppPolicy function will be called.

```PowerShell
$ImportPath = Read-Host -Prompt "Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Policies\policy.json"

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"','')

if(!(Test-Path "$ImportPath")){

Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
Write-Host "Script can't continue..." -ForegroundColor Red
Write-Host
break

}
```

#### Add-ManagedAppPolicy Function
This function is used to add an App Protection policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-ManagedAppPolicy -JSON $JSON
```
