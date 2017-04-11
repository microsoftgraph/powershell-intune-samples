# Intune Managed Device script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. Invoke_DeviceAction_Set.ps1
This script loops through all managed devices assigned to a specified user and runs an action against the device in the Intune Service that you have authenticated with.

The script requests an input of a users principal name.

There are the following functions used:

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
#### Get-AADUserDevices - Function
This function is used to get a users managed devices from within the Intune Service. It supports a requires a single parameter of the users ID found in Azure Active Directory.
```PowerShell
Get-AADUserDevices -UserID e131cdb0-ea2c-4761-9add-d9c64bd9061b
```
#### Invoke-DeviceAction - Function
This function is used to Invoke a device action for a specified device in the Intune Service.

It supports multiple parameters as an input to the function to invoke an device action in the service. For the ResetPasscode, Retire and Wipe it will prompt for confirmation of the action.

```PowerShell
# Remote Lock device configured in Intune
Invoke-DeviceAction -DeviceID 87fdd968-63ba-4a61-b587-25f3bb86bca4 -RemoteLock

# Reset the passcode for the device configured in Intune
Invoke-DeviceAction -DeviceID 87fdd968-63ba-4a61-b587-25f3bb86bca4 -ResetPasscode

# Retire Device configured in Intune
Invoke-DeviceAction -DeviceID 87fdd968-63ba-4a61-b587-25f3bb86bca4 -Retire

# Wipe device configured in Intune
Invoke-DeviceAction -DeviceID 87fdd968-63ba-4a61-b587-25f3bb86bca4 -Wipe

```
### 2. ManagedDeviceOverview_Get.ps1
This script returns a report of all managed devices added to the Intune Service that you have authenticated with.

Sample data which is returned:

```

id                           : 83e9b6b6-154e-4e71-9a23-da7700f6e75c
enrolledDeviceCount          : 2
mdmEnrolledCount             : 2
dualEnrolledDeviceCount      : 0
deviceOperatingSystemSummary : @{androidCount=1; iosCount=1; macOSCount=0; windowsMobileCount=0; windowsCount=0}
```

There are the following functions used:

#### Get-ManagedDeviceOverview - Function
This function is used to get the managed device overview from the Intune Service.
```PowerShell
Get-ManagedDeviceOverview
```

### 3. ManagedDevices_Get.ps1
This script returns all managed devices added to the Intune Service that you have authenticated with.

There are the following functions used:

#### Get-ManagedDevices - Function
This function is used to get all managed devices from the Intune Service.
```PowerShell
Get-ManagedDevices
```
#### Get-ManagedDeviceUser - Function
This function is used to get the user assigned to the managed device.
```PowerShell
Get-ManagedDeviceUser -DeviceID 3a81de89-0447-49b6-a866-0ae62a5ad298
```
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
