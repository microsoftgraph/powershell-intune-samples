# Intune Auditing script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. Auditing_Get.ps1
This script shows all audit event categories in the Intune Service that you have authenticated with. It will offer a menu (sample below) of all Audit categories available in the service.
```
Intune Audit Categories:
1. Other
2. Enrollment
3. Compliance
4. DeviceConfiguration
5. Device
6. Application
7. EBookManagement
8. ConditionalAccess
9. OnPremiseAccess
10. Role
11. SoftwareUpdates
12. DeviceSetupConfiguration
```

#### Get-AuditCategories Function
This function is used to get all audit categories in the Intune Service.

```PowerShell
# Returns all audit categories configured in Intune
Get-AuditCategories

```
#### Get-AuditEvents Function
This function is used to get all audit events in the past month from the Intune Service.

```PowerShell
# Returns all audit events for the "Application" category configured in Intune
Get-AuditEvents -Category "Application"

```
