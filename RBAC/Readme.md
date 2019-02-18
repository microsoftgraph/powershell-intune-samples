# Intune Roles script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. RBAC_Add.ps1
This script adds an RBAC Intune Role into the Intune Service that you have authenticated with. The RBAC Intune Role created by the script are shown below in the JSON section below.

#### Add-RBACRole Function
This function is used to add an RBAC Intune Role to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

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
### 2. RBAC_Add_Assign.ps1
This script adds and Assigns an RBAC Intune Role into the Intune Service that you have authenticated with.

#### Add-RBACRole Function
This function is used to add an RBAC Intune Role to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-RBACRole -JSON $JSON
```
#### Assign-RBACRole Function
This function is used to create an Intune Role Assignment with Members and a Scope Group. There are four required parameters to this function.

+ Id - The ID of the Intune Role you want to create an Assignment
+ DisplayName - The display name of the Assignment
+ MemberGroupId - The AAD Group who has the members that can use the effective permissions assigned
+ TargetGroupId - The AAD Group which is used as the Scope Group for which the MemberGroupId can manage

```PowerShell
Assign-RBACRole -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupId $MemberGroupId -TargetGroupId $TargetGroupId
```
#### Get-AADGroup Function
This function is used to get an AAD Group by -GroupName to be used to assign an Intune Role Member or Scope Group.

```PowerShell
$MemberAADGroup = Read-Host -Prompt "Enter the Azure AD Group name for Intune Role Members"

$MemberGroupId = (get-AADGroup -GroupName "$MemberAADGroup").id

    if($MemberGroupId -eq $null -or $MemberGroupId -eq ""){

    Write-Host "AAD Group - '$MemberAADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host

####################################################

$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name for Intune Role Scope"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host
```

### 3. RBAC_DuplicateRole.ps1
This script duplicates an inbuilt role as a custom role into the Intune Service that you have authenticated with.

You will be presented with a menu of the Built-in Roles configured in the Intune Service.

```
Please specify which Intune Role you want to duplicate:

1. Policy and Profile manager
2. School Administrator
3. Help Desk Operator
4. Application Manager
5. Read Only Operator
6.  Intune Role Administrator
```

#### Get-RBACRole Function
This function is used to get all RBAC Intune Roles from the Intune Service.

It supports a single parameter as an input to the function to pull data from the service.

```PowerShell
# Returns all RBAC Intune Roles configured in Intune
Get-RBACRole

# Returns a RBAC Intune Role that contains the Name configured in Intune
Get-RBACRole -Name "Graph RBAC"
```

#### Add-RBACRole Function
This function is used to add an RBAC Intune Role to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

### 4. RBAC_Export.ps1
This script gets all the custom RBAC Intune Roles from the Intune Service that you have authenticated with. The script will then export the Roles to .json format in the directory of your choice.

```PowerShell
$ExportPath = Read-Host -Prompt "Please specify a path to export RBAC Intune Roles to e.g. C:\IntuneOutput"

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
```

#### Get-RBACRole Function
This function is used to get all RBAC Intune Roles from the Intune Service.

```PowerShell
# Returns all RBAC Intune Roles configured in Intune
Get-RBACRole

```

### 5. RBAC_Get.ps1
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

### 6. RBAC_Import_FromJSON.ps1
This script imports from a JSON file an RBAC Intune Role into the Intune Service that you have authenticated with.

When you run the script it will prompt for a path to a .json file, if the path is valid the Add-RBACRole function will be called.

```PowerShell
$ImportPath = Read-Host -Prompt "Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Policies\policy.json"

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"','')

if(!(Test-Path "$ImportPath")){

Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
Write-Host "Script can't continue..." -ForegroundColor Red
Write-Host
break

}
```

#### Add-RBACRole Function
This function is used to add an RBAC Intune Role to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-RBACRole -JSON $JSON
```

### 7. RBAC_Remove.ps1
This script removes an RBAC Intune Role configured in the Intune Service that you have authenticated with.

#### Remove-RBACRole Function
This function is used to remove an RBAC Intune Role from the Intune Service.

It supports a single parameter -roleDefinitionId as an input to the function to specify the id of the RBAC Intune Role that you wish to remove. The script will get a role of choice via the -Name parameter and then remove it if it's valid.

```PowerShell
# Removes an individual compliance policy from the Intune Service
$RBAC_Role = Get-RBACRole -Name "Graph"

Remove-RBACRole -roleDefinitionId $RBAC_Role.id
```
### 8. RBAC_UserStatus.ps1
This script can be used to find a users effective permissions in the Intune console / Graph. The script prompts for a user principal name and if its valid will find which Intune role assignments the user is a Member of which in effect with shown the users permissions.

```
-------------------------------------------------------------------

Display Name: User
User ID: 815f48e9-c108-4524-b9fc-66cf6bbe7b0d
User Principal Name: user@tenant.onmicrosoft.com

Directory Role:
User

AAD Group Membership:
Helpdesk Support
UK Employees

-------------------------------------------------------------------

RBAC Role Assigned - Graph RBAC Role

Assignment Display Name: Assignment

Assignment - Members:
Helpdesk Support

Assignment - Scope (Groups):
UK Employees

-------------------------------------------------------------------

RBAC Role Assigned - All Area Read Only Access

Assignment Display Name: UK Employees

Assignment - Members:
Helpdesk Support

Assignment - Scope (Groups):
UK Employees

-------------------------------------------------------------------

Effective Permissions for user:
Microsoft.Intune_DeviceCompliancePolices_Read
Microsoft.Intune_DeviceConfigurations_Read
Microsoft.Intune_EndpointProtection_Read
Microsoft.Intune_ManagedApps_Read
Microsoft.Intune_ManagedDevices_Read
Microsoft.Intune_MobileApps_Read
Microsoft.Intune_Organization_Read
Microsoft.Intune_RemoteTasks_RebootNow
Microsoft.Intune_RemoteTasks_RemoteLock
Microsoft.Intune_Roles_Read
Microsoft.Intune_TelecomExpenses_Read
Microsoft.Intune_TermsAndConditions_Read
```
The following functions are used within the script with there usage.

#### Get-AADUser Function
This function is used to get a Users properties from Azure Active Directory.
```PowerShell
Get-AADUser -userPrincipalName $UPN

# Gets all the AAD Groups a user is a member of
Get-AADUser -userPrincipalName $UPN -Property MemberOf
```

#### Get-AADGroup Function
This function is used to get an AAD Group by -GroupName where the user is a member of.

#### Get-RBACRole Function
This function is used to get all RBAC Intune Roles from the Intune Service.

It supports a single parameter as an input to the function to pull data from the service.

```PowerShell
# Returns all RBAC Intune Roles configured in Intune
Get-RBACRole

# Returns a RBAC Intune Role that contains the Name configured in Intune
Get-RBACRole -Name "Graph RBAC"
```
#### Get-RBACRoleDefinition Function
This function is used to get an Intune Role definition by specifying the required parameter -id. It will expand roleassignments to see if there are any assignments configured on the role.
```PowerShell
Get-RBACRoleDefinition -id $RBAC_id
```
#### Get-RBACRoleAssignment Function
This function is used to get an assignment from an Intune Role. It will return the Members, Scope Groups and displayName of the assignment.
```PowerShell
Get-RBACRoleAssignment -id $RBAC_Role_Assignments
```

### 9. RBAC_ScopeTags_PolicyAssign.ps1
This script can be used to automatically assign Scope Tags to all configuration and compliance policies configured in the Intune Service.

The script will look for all Scope Tags configured in the Intune Service and then loops through all policies looking for the Scope Tag name in the DisplayName of the policy. If the Scope Tag name is contained in the DisplayName of the policy then the Scope Tag will be added.

#### Get-RBACScopeTag Function
This function is used to get all scope tags configured in the Intune Service you have authenticated with.
```PowerShell
# Lists all Scope Tags configured in Intune
Get-RBACScopeTag

# Gets a Scope Tag by displayName
Get-RBACScopeTag -DisplayName "Test"
```

#### Update-DeviceCompliancePolicy Function
This function is used to update a Device Compliance Policy by specifying the required parameter -id and -JSON.
```PowerShell
Update-DeviceCompliancePolicy -id $Policy.id -JSON $JSON
```

#### Update-DeviceConfigurationPolicy Function
This function is used to update a Device Configuration Policy by specifying the required parameter -id and -JSON.
```PowerShell
Update-DeviceConfigurationPolicy -id $Policy.id -JSON $JSON
```

### 10. RBAC_ScopeTags_PolicyUnAssign.ps1
This script can be used to automatically unassign all Scope Tags from all configuration and compliance policies configured in the Intune Service.

#### Update-DeviceCompliancePolicy Function
This function is used to update a Device Compliance Policy by specifying the required parameter -id and -JSON.
```PowerShell
Update-DeviceCompliancePolicy -id $Policy.id -JSON $JSON
```

#### Update-DeviceConfigurationPolicy Function
This function is used to update a Device Configuration Policy by specifying the required parameter -id and -JSON.
```PowerShell
Update-DeviceConfigurationPolicy -id $Policy.id -JSON $JSON
```

### 11. RBAC_ScopeTags_DeviceAssign.ps1
This script can be used to automatically assign a Scope Tag to an Intune Managed Device enrolled in the Intune Service.

The script will look for all Scope Tags configured in the Intune Service and then assign that scope tag to that individual device. If the scope tag has already been assigned then it will return that its been assigned already. If the Intune Managed Device already has a scope tag assigned, the script will add the already existing scope tags.

#### Get-RBACScopeTag Function
This function is used to get all scope tags configured in the Intune Service you have authenticated with.
```PowerShell
# Lists all Scope Tags configured in Intune
Get-RBACScopeTag

# Gets a Scope Tag by displayName
Get-RBACScopeTag -DisplayName "Test"
```

#### Update-ManagedDevices Function
This function is used to update a Intune Managed Device by specifying the required parameter -id and -JSON.
```PowerShell
Update-ManagedDevices -id $ManagedDevice.id -ScopeTags $ScopeTag
```

### 12. RBAC_ScopeTags_DeviceUnAssign.ps1
This script can be used to automatically unassign all Scope Tags to an Intune Managed Device enrolled in the Intune Service.

#### Update-ManagedDevices Function
This function is used to update a Intune Managed Device by specifying the required parameter -id and -JSON.
```PowerShell
Update-ManagedDevices -id $ManagedDevice.id -ScopeTags ""
```

### 13. RBAC_ScopeTags_ApplicationAssign.ps1
This script can be used to automatically assign a Scope Tag to an Intune Application in the Intune Service.

The script will look for all Scope Tags configured in the Intune Service and then assign that scope tag to that individual application. If the scope tag has already been assigned then it will return that its been assigned already. If the Intune Application already has a scope tag assigned, the script will add the already existing scope tags.

#### Get-RBACScopeTag Function
This function is used to get all scope tags configured in the Intune Service you have authenticated with.
```PowerShell
# Lists all Scope Tags configured in Intune
Get-RBACScopeTag

# Gets a Scope Tag by displayName
Get-RBACScopeTag -DisplayName "Test"
```

#### Update-IntuneApplication Function
This function is used to update an Intune Application by specifying the required parameter -id, -Type and -JSON.
```PowerShell
Update-ManagedDevices -id $Application.id -Type "#microsoft.graph.WebApp" -ScopeTags $ScopeTag
```

### 14. RBAC_ScopeTags_ApplicationUnAssign.ps1
This script can be used to automatically unassign all Scope Tags to an Intune Application in the Intune Service.

#### Update-ManagedDevices Function
This function is used to update an Intune Application by specifying the required parameter -id, -Type and -JSON.
```PowerShell
Update-ManagedDevices -id $Application.id -Type "#microsoft.graph.WebApp" -ScopeTags ""
```
