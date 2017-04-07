# Intune Roles script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. RBAC_Add.ps1
This script adds an RBAC Intune Role into the Intune Service that you have authenticated with. The RBAC Intune Role created by the script are shown below in the JSON section below.

#### Add-RBACRole Function
This function used to add an RBAC Intune Role to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-RBACRole -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-RBACRole function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON files are shown below:

#### Sample JSON

```JSON
{
  "@odata.type": "#microsoft.graph.roleDefinition",
  "displayName": "Graph RBAC Role",
  "description": "New RBAC Role Description",
  "permissions": [
    {
      "@odata.type": "microsoft.graph.permission",
      "actions": [
        "Microsoft.Intune/MobileApps/Read",
        "Microsoft.Intune/TermsAndConditions/Read",
        "Microsoft.Intune/ManagedApps/Read",
        "Microsoft.Intune/ManagedDevices/Read",
        "Microsoft.Intune/DeviceConfigurations/Read",
        "Microsoft.Intune/TelecomExpenses/Read",
        "Microsoft.Intune/Organization/Read",
        "Microsoft.Intune/RemoteTasks/RebootNow",
        "Microsoft.Intune/RemoteTasks/RemoteLock"
      ]
    }
  ],
  "isBuiltInRoleDefinition": false
}
```

### 2. RBAC_Get.ps1
This script gets all the RBAC Intune Roles from the Intune Service that you have authenticated with.

#### Get-RBACRole Function
This function is used to get all RBAC Intune Roles from the Intune Service.

It supports a single parameter as an input to the function to pull data from the service.

```PowerShell
# Returns all RBAC Intune Roles configured in Intune
Get-RBACRole

# Returns a RBAC Intune Role that contains the Name configured in Intune
Get-RBACRole -Name "Graph RBAC"
```

### 3. RBAC_Remove.ps1
This script removes an RBAC Intune Role configured in the Intune Service that you have authenticated with.

#### Remove-RBACRole Function
This function is used to remove an RBAC Intune Role from the Intune Service.

It supports a single parameter -roleDefinitionId as an input to the function to specify the id of the RBAC Intune Role that you wish to remove. The script will get a role of choice via the -Name parameter and then remove it if it's valid.

```PowerShell
# Removes an individual compliance policy from the Intune Service
$RBAC_Role = Get-RBACRole -Name "Graph"

Remove-RBACRole -roleDefinitionId $RBAC_Role.id
```
