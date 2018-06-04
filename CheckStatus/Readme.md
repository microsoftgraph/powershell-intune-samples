# Intune Check Status script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. Check_lastSyncDateTime.ps1
This script returns any Intune Managed Devices that haven't synced with the Intune Service in the past 30 days (default) that you have authenticated with.

#### Variables
Within the script there is the following variable where you can change the amount of days to check.


```PowerShell
# Filter for the minimum number of days where the device hasn't checked in
$days = 30
```

If devices are found they will be returned in the following format.

```
Device Name: DESKTOP-00EUFJK
Management State: managed
Operating System: Windows
Device Type: windowsRT
Last Sync Date Time: 2017-06-07T18:48:12Z
Jail Broken: Unknown
Compliance State: noncompliant
Enrollment Type: azureDomainJoined
AAD Registered: True
Management Agent: mdm
User Principal Name: dave@graphdev.onmicrosoft.com

Date Time difference is 53 days from current date time...
```

### 2. Check_enrolledDateTime.ps1
This script returns any Intune Managed Devices that have enrolled in the Intune Service in the past 24 hours (default) that you have authenticated with.

#### Variables
Within the script there is the following variable where you can change the amount of days to check.


```PowerShell
# Filter for the minimum number of minutes when the device enrolled into the Intune Service

# 1440 = 24 hours
$minutes = 1440
```

If devices are found they will be returned in the following format.

```
Checking if any Intune Managed Device Enrolled Date is within or equal to 1440 minutes...

There are 1 devices enrolled in the past 1440 minutes...
IPADMINI4 - EASMDM - user@tenant.onmicrosoft.com - 2017-08-01T13:11:10Z

------------------------------------------------------------------

Device Name: IPADMINI4
Management State: managed
Operating System: iOS
Device Type: iPad
Last Sync Date Time: 2017-08-01T13:11:10Z
Enrolled Date Time: 2017-08-01T13:11:10Z
Jail Broken: False
Compliance State: compliant
Enrollment Type: userEnrollment
AAD Registered: True
Management Agent: easMdm

Date Time difference is 12 minutes from current date time...
```

### 3. DirectoryRoles_Get.ps1
This sample script shows all Directory Roles from Microsoft Graph that you have authenticated with. It will offer a menu (sample below) of all Directory Roles available.
```
Please specify which Directory Role you want to query for User membership:
1. Company Administrator
2. Device Administrators
3. Directory Readers
4. Directory Synchronization Accounts
5. Helpdesk Administrator
6. Intune Service Administrator
```
Once you have chosen your selection it will show all the users who are members of that specific role.

#### Get-DirectoryRoles Function
This function is used to get all Directory Roles from Microsoft Graph.

```PowerShell
# Returns all Directory Roles from Microsoft Graph
Get-DirectoryRoles
```
