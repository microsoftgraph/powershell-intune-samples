# Intune Apple Enrollment script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. APNS_Get.ps1
This script gets Apple Push Notification Certificate information from the Intune Service that you have authenticated with.

#### Get-ApplePushNotificationCertificate Function
This function is used to get Apple Push Notification Certificate information from the Intune Service.

```PowerShell
# Returns Apple Push Notification Certificate information configured in Intune
Get-ApplePushNotificationCertificate

```
### 2. AppleDEP_Sync.ps1
This script reads the Apple DEP tokens in your Intune tenant and synchronizes with the Apple DEP service. If there are multiple DEP tokens, you will be prompted to select which token you wish to synchronize. The script will not synchronize multiple tokens at once.

WARNING: The Apple DEP service only accepts a synchronization request once every 15 minutes. If you try and synchronize more often than this, the script will inform you that a synchronization is already in progress and will provide the time remaining before another synchronization can occur.

#### Get-DEPOnboardingSettings Function
This function is used to retrieve the DEP onboarding settings from the Intune service
```PowerShell
# Returns Apple DEP onboarding settings configured in Intune
Get-DEPOnboardingSettings

# Returns a specific Apple DEP onboarding token configured in Intune
Get-DEPOnboardingSettings -tokenId $TokenId
```

#### Sync-AppleDEP Function
This function is used to sync a specific Apple DEP token from the Intune service
```PowerShell
# Sync's an Apple DEP token configured in Intune
Sync-AppleDEP -id $id
```

### 3. AppleDEPProfile_Assign.ps1
This script assigns a DEP profile to a device. If there are multiple DEP tokens, you will be prompted to select which token you wish to work with. You will then be prompted for a device serial number, and then presented with a list of DEP profiles. The selected profile will then be assigned to the device.

#### Get-DEPOnboardingSettings Function
This function is used to retrieve the DEP onboarding settings from the Intune service
```PowerShell
# Returns Apple DEP onboarding settings configured in Intune
Get-DEPOnboardingSettings

# Returns a specific Apple DEP onboarding token configured in Intune
Get-DEPOnboardingSettings -tokenId $TokenId
```
#### Get-DEPProfiles Function
This function is used to return the DEP profiles from the Intune service.

```PowerShell
# Returns the DEP profiles configured in Intune based on the selected token
Get-DEPProfiles -id $id
```
#### Assign-ProfileToDevice Function
This function is used to set the DEP profile which the device receives as part of enrolment

```PowerShell
# Assigns DEP profile to DEP device
Assign-ProfileToDevice -DeviceSerialNumber $DeviceSerialNumber -ProfileId $ProfileID
```
