# Intune Compliance Policy script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. CompliancePolicy_Add.ps1
This script adds an iOS and Android policy into the Intune Service that you have authenticated with. The policies created by the script are shown below in the Android and iOS JSON sections below.

#### Add-DeviceCompliancePolicy Function
This function used to add a compliance policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-DeviceCompliancePolicy -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-DeviceCompliancePolicy function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON files are shown below:

#### Android JSON

```JSON
{
"passwordExpirationDays": null,
"requireAppVerify":  true,
"securityPreventInstallAppsFromUnknownSources":  true,
"@odata.type":  "microsoft.graph.androidCompliancePolicy",
"passwordRequiredType":  "numeric",
"storageRequireEncryption":  true,
"storageRequireRemovableStorageEncryption":  true,
"passwordMinutesOfInactivityBeforeLock":  15,
"passwordPreviousPasswordBlockCount":  null,
"passwordRequired":  true,
"description":  "Android Compliance Policy",
"passwordMinimumLength":  4,
"displayName":  "Android Compliance Policy",
"securityBlockJailbrokenDevices":  true,
"deviceThreatProtectionRequiredSecurityLevel":  "low",
"deviceThreatProtectionEnabled":  true,
"securityDisableUsbDebugging":  true
}
```

#### iOS JSON

```JSON
{
"@odata.type": "microsoft.graph.iosCompliancePolicy",
"description": "iOS Compliance Policy",
"displayName": "iOS Compliance Policy",
"passcodeBlockSimple": true,
"passcodeExpirationDays": null,
"passcodeMinimumLength": 4,
"passcodeMinutesOfInactivityBeforeLock": 15,
"passcodePreviousPasscodeBlockCount": null,
"passcodeMinimumCharacterSetCount": null,
"passcodeRequiredType": "numeric",
"passcodeRequired": true,
"securityBlockJailbrokenDevices": true,
"deviceThreatProtectionEnabled": true,
"deviceThreatProtectionRequiredSecurityLevel": "low"
}
```

### 2. CompliancePolicy_Get.ps1
This script gets all the compliance policies from the Intune Service that you have authenticated with.

#### Get-DeviceCompliancePolicy Function
This function is used to get all compliance policies from the Intune Service.

It supports multiple parameters as an input to the function to pull data from the service. Only a single parameter can be used otherwise it will return an "Multiple parameters set, specify a single parameter"

```PowerShell
# Returns all compliance policies configured in Intune
Get-DeviceCompliancePolicy

# Returns a compliance policy that contains the Name configured in Intune
Get-DeviceCompliancePolicy -Name "Android"

# Returns iOS compliance policies configured in Intune
Get-DeviceCompliancePolicy -iOS

# Returns Android compliance policies configured in Intune
Get-DeviceCompliancePolicy -Android

# Returns Windows 10 compliance policies configured in Intune
Get-DeviceCompliancePolicy -Win10

```

### 3. CompliancePolicy_Remove.ps1
This script removes a compliance policy configured in the Intune Service that you have authenticated with.

#### Remove-DeviceCompliancePolicy Function
This function is used to remove a compliance policy from the Intune Service.

It supports a single parameter -id as an input to the function to specify the id of the compliance policy that you wish to remove. The script will get a policy of choice via the -Name parameter and then remove it if it's valid.

```PowerShell
# Removes an individual compliance policy from the Intune Service
$CP = Get-DeviceCompliancePolicy -Name "Test Policy"

Remove-DeviceCompliancePolicy -id $CP.id
```
