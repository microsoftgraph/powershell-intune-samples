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

### 3.ManagedDevices_Add_ToAADGroup.ps1

This script adds Intune managed devices as assigned members to an Azure AD Device Security Group when the associated user’s Azure AD user name contains a specific string.  For example, if a username is: "Aimee Bowman (Redmond)" – the script can add Aimee’s managed devices to an Azure AD Security Group called "Redmond Devices."

The script iterates through all Intune managed devices and then identifies the associated user for each managed device. The script retrieves the Azure AD user’s name, and checks to see if the name contains the value defined in the $FilterName variable.  If found, the users’ associated Intune managed device is added to the specified Azure Active Directory Group as an assigned entry.  If the device is already in the Group then it won't attempt to add the device to the group.

The script will prompt for two variables: $AADGroup and $FilterName.  When you run the script, input those two values to match the requirements for your organization.  Note that the filter string (search string) is case sensitive, and should not contain quotes when entered on the command line.

There are the following extra functions used:

#### Add-AADGroupMember - Function
This function is used to add an Azure Active Directory Member (User / Device) to a specified AAD Group.
```PowerShell
Add-AADGroupMember -GroupId "Devices Group" -AADMemberID 3a81de89-0447-49b6-a866-0ae62a5ad298
```

#### Get-AADDevice - Function
This function is used to get an AAD device information from Azure Active Directory.
```PowerShell
Get-AADDevice -DeviceID 3a81de89-0447-49b6-a866-0ae62a5ad298

```

#### Get-AADGroup - Function
This function is used to get all managed devices from the Intune Service.
```PowerShell
# Returns all AAD Groups registered with Azure AD
Get-AADGroup

# Returns all users registered with Azure AD
Get-AADGroup -id 7a81de89-0447-49b6-a866-0ae62a5ad298

# Returns all users registered with Azure AD
Get-AADGroup -GroupName "Devices Group"

```

### 4. ManagedDevices_Get.ps1
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
