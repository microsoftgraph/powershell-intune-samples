# Intune App Protection Policy script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. ManagedAppPolicy_Add.ps1
This script adds an App Protection policy into the Intune Service that you have authenticated with. The policies created by the script are shown below in the Android and iOS JSON sections below.

#### Add-ManagedAppPolicy Function
This function used to add an App Protection policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

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

  "mobileAppIdentifierDeployments": [
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

  "mobileAppIdentifierDeployments": [
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

### 2. ManagedAppPolicy_Get.ps1
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

### 3. ManagedAppPolicy_Remove.ps1
This script removes an App Protection policy configured in the Intune Service that you have authenticated with.

#### Remove-ManagedAppPolicy Function
This function is used to remove a App Protection policy from the Intune Service.

It supports a single parameter -id as an input to the function to specify the id of the App Protection policy that you wish to remove. The script will get a policy of choice via the -Name parameter and then remove it if it's valid.

```PowerShell
# Removes an individual App Protection policy from the Intune Service
$MAM = Get-ManagedAppPolicy -Name "Test Policy"

Remove-ManagedAppPolicy -id $MAM.id
```
