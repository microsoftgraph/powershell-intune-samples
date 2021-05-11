# Filters (preview) script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. IntuneFilter_Export.ps1
This script gets all the Intune Filters from the Intune Service that you have authenticated with. The script will then export the filters to .json format in the directory of your choice.

```PowerShell
$ExportPath = Read-Host -Prompt "Please specify a path to export Intune Filters to e.g. C:\IntuneOutput"

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

#### Get-IntuneFilter Function
This function is used to get all Intune Filters from the Intune Service.

```PowerShell
# Returns all Intune Filters configured in Intune
Get-IntuneFilter
```

#### Export-JSONData Function
This function is used to export the policy information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```

### 2. IntuneFilter_Get.ps1
This script gets all Intune Filters from the Intune Service that you have authenticated with.

#### Get-IntuneFilter Function
This function is used to get all Intune Filters from the Intune Service.

```PowerShell
# Returns all Intune Filters configured in Intune
Get-IntuneFilter
```

### 3. IntuneFilter_Import_FromJSON.ps1
This script imports from a JSON file an Intune Filter into the Intune Service that you have authenticated with.

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

#### Add-IntuneFilter Function
This function is used to add an Intune Filter to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-IntuneFilter -JSON $JSON
```

### 4. AssociatedFilter_Get.ps1
This script checks if an Intune Filter specified is used across any of the elements in Intune that support the Filters (preview) that you have authenticated with.

When you run the script it will prompt for a filter name configured in the tenant, if the display name is valid via the Get-IntuneFilter function the script will continue.

```PowerShell
write-host "Filters Name:" -f Yellow
$FilterName = Read-Host

if($FilterName -eq $null -or $FilterName -eq ""){

    write-host "Filter Name is Null..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break

}
```
#### Get-IntuneFilter Function
This function is used to get all Intune Filters from the Intune Service.

```PowerShell
# Returns all Intune Filters configured in Intune
Get-IntuneFilter
```

If a filter is found the script will output the information about the filter
```
Filter found...
Filter Id:        eebd25bd-4b25-4d46-ab5c-6cc07b801b79
Filter Name:      Android Enterprise - Google Devices
Filter Platform:  androidForWork
Filter Rule:      (device.manufacturer -eq "Google")
Filter Scope Tag: 0
```

Once and Intune Filter has been found and verified as a single entry, the script will look through the following element types to check if the Intune Filter is being used.

- Compliance Policies
- Configuration Policies
- Settings Catalog Policies
- Administrative Template Policies
- Intune Applications

Once this is complete the script will return "Overall Analysis" of where the filter is being used.
```
-------------------------------------------------------------------
Overall Analysis
-------------------------------------------------------------------
Status of each area of MEM that support Filters assignment status

Applicable OS Type: androidForWork

Compliance Policies:            1
Device Configuration Policies:  1
Settings Catalog Policies:      0
Administrative Templates:       0
Intune Applications:            0

Total Filters Assigned: 2
```
