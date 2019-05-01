# Intune User Policy Report script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. User_Policy_Report_Get.ps1
This script returns all devices and policies that apply to a specified user from the Intune Service that you have authenticated with.

The script requests an input of a users principal name and then will check the following:

* Check if the user has any devices registered in Intune
* Check which SKUs have been Assigned
* Check which AAD groups the user is a member of
* Take the users AAD group membership and check if any policies have that group assignment

The output of the script will return the following:

```
User Principal Name:
user@tenant.onmicrosoft.com

Display Name: Tenant User
User ID: eb954d5c-44fd-4c47-87a7-619c4b77101e
User Principal Name: user@tenant.onmicrosoft.com

User Devices:
Device Name: Android_3/13/2017_3:57 PM
Owner Type: personal
Last Sync Date: 2017-03-29T21:16:05.3621034Z
OS: Android
OS Version: 6.0.1
EAS Activated: True
AAD Registered: True
Enrollment Type: userEnrollment
Management State: managed
Compliance State: compliant

User Assigned Skus:
b05e124f-c7cc-45a0-a6aa-8cf78c946968
c7df2760-2c81-4ef7-b578-5b5392b571df

AAD Group Membership:
Company Employees

Device Compliance Policies:
Android Compliance Policy

Device Configuration Policies:
No Device Configuration Policies Assigned
```

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
#### Get-DeviceCompliancePolicy - Function
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
#### Get-DeviceCompliancePolicyAssignment - Function
This function is used to get any compliance policy assignments from the Intune Service. It requires a single parameter of id to pull the assignment from the compliance policy.
```PowerShell
Get-DeviceCompliancePolicyAssignment -id 4dccb81f-18db-4b7e-9a4e-b90c2980d0c3
```
#### Get-DeviceConfigurationPolicy - Function
This function is used to get all device configuration policies from the Intune Service.

It supports a single parameter -Name where you can specify the display name of the policy you wish to return.
```PowerShell
# Returns all compliance policies configured in Intune
Get-DeviceConfigurationPolicy

# Returns a compliance policy that contains the Name configured in Intune
Get-DeviceConfigurationPolicy -Name "Android"
```
#### Get-DeviceConfigurationPolicyAssignment - Function
This function is used to get any device configuration policy assignments from the Intune Service.

It requires a single parameter of id to pull the assignment from the configuration policy.
```PowerShell
Get-DeviceConfigurationPolicyAssignment -id 4dccb81f-18db-4b7e-9a4e-b90c2980d0c3
```
## 2. User_MAM_Report_Get.ps1

This script retrieves all assigned app configuration and app protection policies assigned to a user, and which applications they are targeted to. The script can be used to troubleshoot user issues as well as validate configurations and expected experience at the device level.

#### Get-AADUser Function
This function is used to get AAD Users from the Graph API REST interface

#### Get-AADGroup Function
This function is used to get AAD Groups from the Graph API REST interface

#### Get-ManagedAppPolicy Function
This function is used to get managed app policies (AppConfig) from the Graph API REST interface

#### Get-ManagedAppProtection Function
This function is used to get managed app protection configuration from the Graph API REST interface

#### Get-ApplicationAssignment Function
This function is used to get an application assignment from the Graph API REST interface

#### Get-MobileAppConfigurations Function
This function is used to get all Mobile App Configuration Policies (managed device) using the Graph API REST interface

#### Get-TargetedManagedAppConfigurations Function
This function is used to get all Targeted Managed App Configuration Policies using the Graph API REST interface

#### Get-IntuneApplication Function
This function is used to get applications from the Graph API REST interface

#### Get-IntuneMAMApplication Function
This function is used to get MAM applications from the Graph API REST interface

