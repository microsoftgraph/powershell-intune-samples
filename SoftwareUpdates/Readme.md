# Intune Software Update Policy script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. SoftwareUpdates_Get.ps1
This script gets all the Software Update policies from the Intune Service that you have authenticated with.

#### Get-SoftwareUpdatePolicy Function
This function is used to get all Software Update policies from the Intune Service.

It supports a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns Windows 10 Software Update policies configured in Intune
Get-SoftwareUpdatePolicy -Windows10

# Returns iOS Software Update policies configured in Intune
Get-SoftwareUpdatePolicy -iOS
```

### 2. Windows10_SoftwareUpdates_Add.ps1
This script adds a Software Update policy into the Intune Service that you have authenticated with. The Windows 10 Software Update policy created by the script is shown below in the sample JSON section.

#### Add-DeviceConfigurationPolicy Function
This function is used to add a device configuration policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-DeviceConfigurationPolicy -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-DeviceCompliancePolicy function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON files are shown below:

#### Windows 10 Software Update JSON

```JSON
{

"displayName":"Windows 10 - Semi-Annual (Targeted)",
"description":"Windows 10 - Semi-Annual (Targeted)",
"@odata.type":"#microsoft.graph.windowsUpdateForBusinessConfiguration",
"businessReadyUpdatesOnly":"all",
"microsoftUpdateServiceAllowed":true,
"driversExcluded":false,
"featureUpdatesDeferralPeriodInDays":0,
"qualityUpdatesDeferralPeriodInDays":0,
"automaticUpdateMode":"autoInstallAtMaintenanceTime",
"deliveryOptimizationMode":"httpOnly",

    "installationSchedule":{
    "@odata.type":"#microsoft.graph.windowsUpdateActiveHoursInstall",
    "activeHoursStart":"08:00:00.0000000",
    "activeHoursEnd":"17:00:00.0000000"
    }

}
```
### 3. Windows10_SoftwareUpdates_Add_Assign.ps1
This script adds and Assigns Software Update policy into the Intune Service that you have authenticated with.

#### Add-DeviceConfigurationPolicy Function
This function is used to add a device configuration policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-DeviceConfigurationPolicy -JSON $JSON
```

#### Add-DeviceConfigurationPolicyAssignment Function
This function is used to assign a policy to an AAD Group. This function has two required parameters.

+ ConfigurationPolicyId - The policy ID defined in the Intune Service
+ TargetGroupId - The AAD Group ID where the policy should be assigned

```PowerShell
Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult.id -TargetGroupId $TargetGroupId
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

### 4. SoftwareUpdates_Export.ps1
This script gets all the Software Update policies from the Intune Service that you have authenticated with. The script will then export the policy to .json format in the directory of your choice.

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

#### Get-SoftwareUpdatePolicy Function
This function is used to get all Software Update policies from the Intune Service.

It supports a single parameter as an input to the function to pull data from the service.

```PowerShell
# Returns Windows 10 Software Update policies configured in Intune
Get-SoftwareUpdatePolicy -Windows10

# Returns iOS Software Update policies configured in Intune
Get-SoftwareUpdatePolicy -iOS
```

#### Export-JSONData Function
This function is used to export the policy information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```

### 5. SofwareUpdates_Import_FromJSON.ps1
This script imports from a JSON file a Software update policy into the Intune Service that you have authenticated with.

When you run the script it will prompt for a path to a .json file, if the path is valid the Add-DeviceConfigurationPolicy function will be called.

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

#### Add-DeviceConfigurationPolicy Function
This function is used to add a device configuration / Software Update policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-DeviceConfigurationPolicy -JSON $JSON
```
