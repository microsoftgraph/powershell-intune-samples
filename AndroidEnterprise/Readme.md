# Intune Android Enterprise script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. Get-AndroidDedicatedDeviceProfiles.ps1
This script gets any Android Dedicated Device Profile from the Intune Service that you have authenticated with.

#### Get-AndroidEnrollmentProfile - Function
This function is used to get Android Device Owner Enrollment Profiles from the Intune Service.

```PowerShell
# Returns Android Device Owner Enrollment Profile information configured in Intune
Get-AndroidEnrollmentProfile
```

If a profile is found the following JSON will be returned.

```JSON
accountId               : abc123d4-1111-2222-3333-444444444444
id                      : abc123d4-1111-2222-3333-444444444444
displayName             : DDProfile_US
description             : Dedicated Device Profile
createdDateTime         : 2018-11-06T16:44:24.3830742Z
lastModifiedDateTime    : 2018-12-12T08:41:00.1895173Z
tokenValue              :
tokenCreationDateTime   : 2018-11-06T14:44:26.1194324Z
tokenExpirationDateTime : 2019-02-04T19:44:17.142Z
enrolledDeviceCount     : 23
qrCodeContent           :
qrCodeImage             :
```

### 2. Get-AndroidDedicatedDeviceQRCode.ps1
This script retrieves the QR code image from a given Dedicated Device Enrollment Profile, and saves it in a temp location. If there are multiple enrollment profiles, you will be prompted to select which one to work with.

#### Get-AndroidEnrollmentProfile - Function
This function is used to get Android Device Owner Enrollment Profiles from the Intune Service.

```PowerShell
# Returns Android Device Owner Enrollment Profile information configured in Intune
Get-AndroidEnrollmentProfile
```

If a profile is found the following JSON will be returned.

```JSON
accountId               : abc123d4-1111-2222-3333-444444444444
id                      : abc123d4-1111-2222-3333-444444444444
displayName             : DDProfile_US
description             : Dedicated Device Profile
createdDateTime         : 2018-11-06T16:44:24.3830742Z
lastModifiedDateTime    : 2018-12-12T08:41:00.1895173Z
tokenValue              :
tokenCreationDateTime   : 2018-11-06T14:44:26.1194324Z
tokenExpirationDateTime : 2019-02-04T19:44:17.142Z
enrolledDeviceCount     : 23
qrCodeContent           :
qrCodeImage             :
```

#### Get-AndroidQRCode - Function
This function is used to get Android Device Owner Enrollment Profile QRCode Image exported from the Intune Service.

The function uses the following variables to define the path to export the QRCode Image.
```PowerShell
$parent = [System.IO.Path]::GetTempPath()
[string] $name = [System.Guid]::NewGuid()
```

```PowerShell
# Gets an Android QR Code from the specified Android Enrollment Profile ID
Get-AndroidQRCode -Profileid $ProfileID
```

The function will show the following warning before export.
```
- You are about to export the QR code for the Dedicated Device Enrollment Profile 'Profile Name'
- Anyone with this QR code can Enrol a device into your tenant. Please ensure it is kept secure.
- If you accidentally share the QR code, you can immediately expire it in the Intune UI.
- Devices already enrolled will be unaffected.
```
### 3. Get-AndroidWorkProfileConfiguration.ps1
This script queries the Intune Service and retrieves if Android Work profiles have been enabled in Enrollment Restriction configuration. If a configuration is found it will list the AAD Groups assigned else state that no assignments have been configured.
```
-------------------------------------------------------------------
Android Work Profile Configuration
-------------------------------------------------------------------

Android Work Profile 'Test Work Profile Users' with priority 1 configured...
No Assignments for Platform restriction configured...

Android Work Profile 'Android for Work users fbe162e7-4aa0-4020-9f43-1d22576a7f76' with priority 2 configured...
AAD Groups assigned...
AFW Users
```
#### Get-DeviceEnrollmentConfigurations - Function
This function is used to return the device enrollment configuration from the Intune Service.

```PowerShell
# Returns all device enrollment configurations configured in Intune
Get-DeviceEnrollmentConfigurations
```

#### Get-AADGroup - Function
This function is used to get all Azure Active Directory groups configured. It supports multiple parameters for getting data.
```PowerShell
# Gets all AAD groups
Get-AADGroup

# Get AAD group by id
Get-AADGroup -id 4dccb81f-18db-4b7e-9a4e-b90c2980d0c3

# Gets an AAD Group by Group / Display Name
Get-AADGroup -GroupName "Test Group"

# Gets an AAD Group by ID and displays the members of that group
Get-AADGroup -id 4dccb81f-18db-4b7e-9a4e-b90c2980d0c3 -Members
```
