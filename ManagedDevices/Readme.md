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

# Delete device configured in Intune
Invoke-DeviceAction -DeviceID 87fdd968-63ba-4a61-b587-25f3bb86bca4 -Delete
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

### 4.ManagedDevices_Apps_Get.ps1
This script is used to return all Managed Devices application installation inventory. The following output is a sample output.
```
Device found: DESKTOP-00EUFJK

Device Ownership: company

displayName                            version
-----------                            -------
Microsoft.NET.Native.Runtime.1.4       1.4.24201.0
Microsoft.NET.Native.Runtime.1.3       1.3.23901.0
Microsoft.NET.Native.Framework.1.3     1.3.24201.0
Microsoft.VCLibs.140.00                14.0.24123.0
Microsoft.3DBuilder                    13.0.10349.0
Microsoft.BingWeather                  4.18.56.0
Microsoft.DesktopAppInstaller          1.1.25002.0
Microsoft.Getstarted                   4.5.6.0
Microsoft.Messaging                    3.2.24002.0
Microsoft.Microsoft3DViewer            1.1702.21039.0
Microsoft.MicrosoftOfficeHub           2017.311.255.0
Microsoft.MicrosoftSolitaireCollection 3.14.1181.0
Microsoft.MicrosoftStickyNotes         1.4.101.0
Microsoft.MSPaint                      1.1702.28017.0
Microsoft.Office.OneNote               2015.7668.58071.0
Microsoft.OneConnect                   2.1701.277.0
Microsoft.People                       2017.222.1920.0
Microsoft.SkypeApp                     11.8.204.0
Microsoft.StorePurchaseApp             1.0.454.0
Microsoft.Wallet                       1.0.16328.0
Microsoft.Windows.Photos               2016.511.9510.0
Microsoft.WindowsAlarms                2017.203.236.0
Microsoft.WindowsCalculator            2017.131.1904.0
Microsoft.WindowsCamera                2017.125.40.0
microsoft.windowscommunicationsapps    2015.7906.42257.0
Microsoft.WindowsFeedbackHub           1.1612.10312.0
Microsoft.WindowsMaps                  2017.209.105.0
Microsoft.WindowsSoundRecorder         2017.130.1208.0
Microsoft.WindowsStore                 11701.1001.874.0
Microsoft.XboxApp                      2017.113.1250.0
Microsoft.XboxGameOverlay              1.15.2003.0
Microsoft.XboxIdentityProvider         2016.719.1035.0
Microsoft.XboxSpeechToTextOverlay      1.14.2002.0
Microsoft.ZuneMusic                    2019.16112.11621.0
Microsoft.ZuneVideo                    2019.16112.11601.0
9E2F88E3.Twitter                       5.7.1.0
Microsoft.BingNews                     4.20.1102.0
ThumbmunkeysLtd.PhototasticCollage     2.0.74.0
Microsoft.NET.Native.Framework.1.6     1.6.24903.0
KeeperSecurityInc.Keeper               10.2.1.0
Microsoft.NET.Native.Runtime.1.6       1.6.24903.0
Microsoft.Services.Store.Engagement    10.0.1610.0
Microsoft.Advertising.Xaml             10.1705.4.0
Microsoft.VCLibs.120.00                12.0.21005.1
flaregamesGmbH.RoyalRevolt2            3.2.0.0
king.com.CandyCrushSodaSaga            1.91.500.0
A278AB0D.MarchofEmpires                2.4.0.9


Device found: IPADMINI4

Device Ownership: personal

displayName version
----------- -------
Comp Portal 51.1706002.000
```
The following functions are used:

#### Get-ManagedDevices - Function
This function is used to get all managed devices from the Intune Service.
```PowerShell
Get-ManagedDevices
```
### 5. ManagedDevices_DeviceOwnership_Set.ps1
This script returns all managed devices added to the Intune Service that you have authenticated with.

There are the following functions used:

#### Get-ManagedDevices - Function
This function is used to get all managed devices from the Intune Service.
```PowerShell
Get-ManagedDevices
```
#### Set-ManagedDevices - Function
This function is used to set a managed device Ownership from the Intune Service. It has two mandatory parameters -id and -ownertype.

+ id - The ID of the managed device in the Intune Service
+ ownertype - The owner type of the device i.e. personal or company
```PowerShell
Set-ManagedDevice -id $ManagedDevice.id -ownertype company
```

### 6. ManagedDevices_Get.ps1
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
### 7. ManagedDevices_Hardware_Get.ps1
This script returns all managed devices hardware information that have been added to the Intune Service that you have authenticated with.

The script will prompt for an output Directory so that it can export a CSV of the managed device hardware information.

```PowerShell
$ExportPath = Read-Host -Prompt "Please specify a path to export Managed Devices hardware data to e.g. C:\IntuneOutput"

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

Write-Host
```

There are the following functions used:

#### Get-ManagedDevices - Function
This function is used to get all managed devices from the Intune Service.
```PowerShell
Get-ManagedDevices
```

### 8. Win10_PrimaryUser_Get.ps1
This script returns the Primary user of an Intune managed Windows 10 device when provided a device name and it will also the Registered Owner and Registered Users on the associated Azure AD device object.

##### Example usage
```
# Gets all win10 devices and outputs Intune Primary User, Registered Owner and Registered User
.\Win10_PrimaryUser_Get.ps1

# Get specific Win10 device and outputs Intune Primary User, Registered Owner and Registered User
.\Win10_PrimaryUser_Get.ps1 -DeviceName c7e9d83a-085e-4886-989b-b4ee1d68c5a4
```

##### Example output
```
Device name: WIN10-01
Intune device id: e774b98b-9e40-457d-a8b1-d396030b01ab
Intune Primary user id: 815f48e9-c108-4524-b9fc-66cf6bbe7b0d

AAD Registered Owner:
Id: 815f48e9-c108-4524-b9fc-66cf6bbe7b0d
Name: Test User

RegisteredUsers:
Id: 815f48e9-c108-4524-b9fc-66cf6bbe7b0d
Name: Test User
```

#### Get-AADDeviceId - Function
This gets an AAD device object id from the Intune AAD device id
```PowerShell
Get-AADDeviceId -deviceId c7e9d83a-085e-4886-989b-b4ee1d68c5a4”
```

#### Get-Win10IntuneManagedDevice – Function
This function is used to return Intune managed Windows 10 devices only

```PowerShell
Get-Win10IntuneManagedDevice -deviceName “DESKTOP-123456”
```

#### Get-IntuneDevicePrimaryUser - Function
This function is used to get an Intune managed device's Primary User

```PowerShell
Get-IntuneDevicePrimaryUser -deviceId c7e9d83a-085e-4886-989b-b4ee1d68c5a4
```

#### Get-AADDevicesRegisteredOwners - Function
This function is used to get the AAD device registered owner when provided the AAD deviceID

```PowerShell
Get-AADDevicesRegisteredOwners -deviceId $aadDeviceId
```
#### Get-AADDevicesRegisteredUsers - Function
This function is used to get the AAD device registered users when provided the AAD deviceID
```PowerShell
Get-AADDevicesRegisteredUsers -deviceId $aadDeviceId
```

### 9. Win10_PrimaryUser_Set.ps1
This script can be used to set an Intune managed Windows 10 device Primary user when provided a device name and User ID.

##### Example usage
```
.\Win10_PrimaryUser_Set.ps1 -DeviceName c7e9d83a-085e-4886-989b-b4ee1d68c5a4 -UserPrincipalName user@tenant.onmicrosoft.com
```

#### Set-IntuneDevicePrimaryUser - Function
This updates the Intune device primary user
```PowerShell
Set-IntuneDevicePrimaryUser -IntuneDeviceId c7e9d83a-085e-4886-989b-b4ee1d68c5a4 -userId 5f801fed-661e-4f43-8dd5-9ff034047307
```

### 10. Win10_PrimaryUser_Delete.ps1
This script can be used to remove the primary user from an Intune managed Windows 10 device.

##### Example usage
```
.\Win10_PrimaryUser_Delete.ps1 -DeviceName c7e9d83a-085e-4886-989b-b4ee1d68c5a4
```

#### Delete-IntuneDevicePrimaryUser - Function
This function deletes the Intune device primary user when provided a DeviceID

```PowerShell
Delete-IntuneDevicePrimaryUser -IntuneDeviceId c7e9d83a-085e-4886-989b-b4ee1d68c5a4”
```
