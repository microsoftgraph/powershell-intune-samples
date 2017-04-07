# Intune Remote Action Audit script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. RemoteActionAudit_Get.ps1
This script returns all the remote action audit sent from the Intune Service that you have authenticated with.

#### Get-RemoteActionAudit Function
This function is used to get all the remote action audit entries from the Intune Service.


```PowerShell
# Returns all device audit events sent from the Intune Service
Get-RemoteActionAudit

```
