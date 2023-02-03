# Intune Settings Catalog (preview) Policy script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.


### 1. SettingsCatalog_Export.ps1
This script gets all the settings catalog policies from the Intune Service that you have authenticated with. The script will then export the policy to .json format in the directory of your choice.

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

#### Get-SettingsCatalogPolicy Function
This function is used to get all settings catalog policies from the Intune Service.

It supports a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns any Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy

# Returns any Windows 10 Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform windows10

# Returns any MacOS Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform macOS

```

#### Export-JSONData Function
This function is used to export the policy information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```


### 2. SettingsCatalog_Get.ps1
This script gets all the settings catalog policies from the Intune Service that you have authenticated with.

#### Get-SettingsCatalogPolicy Function
This function is used to get all settings catalog policies from the Intune Service.

It supports a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns any Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy

# Returns any Windows 10 Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform windows10

# Returns any MacOS Settings Catalog policies configured in Intune
Get-SettingsCatalogPolicy -Platform macOS

```

### 3. SettingsCatalog_Import_FromJSON.ps1
This script imports from a JSON file a settings catalog policy into the Intune Service that you have authenticated with.

When you run the script it will prompt for a path to a .json file, if the path is valid the Add-SettingsCatalogPolicy function will be called.

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

#### Add-SettingsCatalogPolicy Function
This function is used to add a settings catalog policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-SettingsCatalogPolicy -JSON $JSON
```
