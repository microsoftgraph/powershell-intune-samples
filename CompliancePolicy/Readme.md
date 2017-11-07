# Intune Compliance Policy script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. CompliancePolicy_Add.ps1
This script adds an iOS and Android policy into the Intune Service that you have authenticated with. The policies created by the script are shown below in the Android and iOS JSON sections below.

#### Add-DeviceCompliancePolicy Function
This function used to add a compliance policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-DeviceCompliancePolicy -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-DeviceCompliancePolicy function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON files are shown below:

#### Android JSON

```JSON
{
"passwordExpirationDays": null,
"requireAppVerify":  true,
"securityPreventInstallAppsFromUnknownSources":  true,
"@odata.type":  "microsoft.graph.androidCompliancePolicy",
"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
"passwordRequiredType":  "numeric",
"storageRequireEncryption":  true,
"storageRequireRemovableStorageEncryption":  true,
"passwordMinutesOfInactivityBeforeLock":  15,
"passwordPreviousPasswordBlockCount":  null,
"passwordRequired":  true,
"description":  "Android Compliance Policy",
"passwordMinimumLength":  4,
"displayName":  "Android Compliance Policy",
"securityBlockJailbrokenDevices":  true,
"deviceThreatProtectionRequiredSecurityLevel":  "low",
"deviceThreatProtectionEnabled":  true,
"securityDisableUsbDebugging":  true
}
```

#### iOS JSON

```JSON
{
"@odata.type": "microsoft.graph.iosCompliancePolicy",
"description": "iOS Compliance Policy",
"displayName": "iOS Compliance Policy",
"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
"passcodeBlockSimple": true,
"passcodeExpirationDays": null,
"passcodeMinimumLength": 4,
"passcodeMinutesOfInactivityBeforeLock": 15,
"passcodePreviousPasscodeBlockCount": null,
"passcodeMinimumCharacterSetCount": null,
"passcodeRequiredType": "numeric",
"passcodeRequired": true,
"securityBlockJailbrokenDevices": true,
"deviceThreatProtectionEnabled": true,
"deviceThreatProtectionRequiredSecurityLevel": "low"
}
```
### 2. CompliancePolicy_Add_Assign.ps1
This script adds and assigns a compliance policy into the Intune Service that you have authenticated with.

#### Add-DeviceCompliancePolicy Function
This function used to add a compliance policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-DeviceCompliancePolicy -JSON $JSON
```

#### Add-DeviceCompliancePolicyAssignment Function
This function is used to assign a policy to an AAD Group. This function has two required parameters.

+ CompliancePolicyId - The policy ID defined in the Intune Service
+ TargetGroupId - The AAD Group ID where the policy should be assigned

```PowerShell
Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $id -TargetGroupId $TargetGroupId
```
#### Get-AADGroup Function
This function is used to get an AAD Group by -GroupName to be used to assign to the policy.

```PowerShell
$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name for Policy assignment"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host
```
### 3. CompliancePolicy_Export.ps1
This script gets all the compliance policies from the Intune Service that you have authenticated with. The script will then export the policy to .json format in the directory of your choice.

```PowerShell
$ExportPath = Read-Host -Prompt "Please specify a path to export the policy data to e.g. C:\IntuneOutput"

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

#### Get-DeviceCompliancePolicy Function
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

#### Export-JSONData Function
This function is used to export the policy information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```


### 4. CompliancePolicy_Get.ps1
This script gets all the compliance policies from the Intune Service that you have authenticated with.

#### Get-DeviceCompliancePolicy Function
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

### 5. CompliancePolicy_Import_FromJSON.ps1
This script imports from a JSON file a compliance policy into the Intune Service that you have authenticated with.

When you run the script it will prompt for a path to a .json file, if the path is valid the Add-DeviceCompliancePolicy function will be called.

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

#### Add-DeviceCompliancePolicy Function
This function used to add a compliance policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-DeviceCompliancePolicy -JSON $JSON
```

### 6. CompliancePolicy_Remove.ps1
This script removes a compliance policy configured in the Intune Service that you have authenticated with.

#### Remove-DeviceCompliancePolicy Function
This function is used to remove a compliance policy from the Intune Service.

It supports a single parameter -id as an input to the function to specify the id of the compliance policy that you wish to remove. The script will get a policy of choice via the -Name parameter and then remove it if it's valid.

```PowerShell
# Removes an individual compliance policy from the Intune Service
$CP = Get-DeviceCompliancePolicy -Name "Test Policy"

Remove-DeviceCompliancePolicy -id $CP.id
```
