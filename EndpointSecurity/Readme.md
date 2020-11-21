# Intune Endpoint Security Policy script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. EndpointSecurityPolicy_Export.ps1
This script gets all Endpoint Security policies from the Intune Service that you have authenticated with. The script will then export the policy to .json format in the directory of your choice.

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
#### Get-EndpointSecurityTemplate Function
This function is used to get all Endpoint Security Templates available in the Intune service for your tenant.

```PowerShell
# Returns all Endpoint Security Templates configured in Intune
Get-EndpointSecurityTemplate
```

#### Get-EndpointSecurityPolicy Function
This function is used to get all Endpoint Security policies from the Intune Service.

```PowerShell
# Returns all Endpoint Security policies configured in Intune
Get-EndpointSecurityPolicy
```

#### Get-EndpointSecurityTemplateCategory Function
This function is used to get all Endpoint Security categories from a specific template available in the Intune Service.

It requires a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns all Endpoint Security categories from a template available in Intune
Get-EndpointSecurityTemplateCategory -TemplateId $TemplateId
```

#### Get-EndpointSecurityCategorySetting Function
This function is used to get an Endpoint Security category setting from a specific policy available in the Intune Service.

It requires multiple parameters as an input to the function to pull data from the service.

```PowerShell
# Returns a specific setting from an Endpoint Security policy category configured in Intune
Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
```

#### Export-JSONData Function
This function is used to export the policy information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```

#### Export JSON sample
In the JSON you will find the following extra properties which are used for the import of the policy. Example below:

```PowerShell
"TemplateDisplayName": "Windows Security experience",
"TemplateId": "da332b88-bd29-4def-a442-e0993ed08e24",
"versionInfo": "2005",
```

### 2. EndpointSecurityPolicy_Get.ps1
This script gets all the Endpoint Security policies from the Intune Service that you have authenticated with.

#### Get-EndpointSecurityTemplate Function
This function is used to get all Endpoint Security Templates available in the Intune service for your tenant.

```PowerShell
# Returns all Endpoint Security Templates configured in Intune
Get-EndpointSecurityTemplate
```

#### Get-EndpointSecurityPolicy Function
This function is used to get all Endpoint Security policies from the Intune Service.

```PowerShell
# Returns all Endpoint Security policies configured in Intune
Get-EndpointSecurityPolicy
```

#### Get-EndpointSecurityTemplateCategory Function
This function is used to get all Endpoint Security categories from a specific template available in the Intune Service.

It requires a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns all Endpoint Security categories from a template available in Intune
Get-EndpointSecurityTemplateCategory -TemplateId $TemplateId
```

#### Get-EndpointSecurityCategorySetting Function
This function is used to get an Endpoint Security category setting from a specific policy available in the Intune Service.

It requires multiple parameters as an input to the function to pull data from the service.

```PowerShell
# Returns a specific setting from an Endpoint Security policy category configured in Intune
Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
```

### 3. EndpointSecurityPolicy_Import_FromJSON.ps1
This script imports from a JSON file an Endpoint Security policy into the Intune Service that you have authenticated with.

When you run the script it will prompt for a path to a .json file, if the path is valid the Add-EndpointSecurityPolicy function will be called.

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

#### JSON Import Exclusions
As the export added extra properties, once the JSON is exported the following properties will be excluded as part of the Add-EndpointSecurityPolicy function.

* TemplateDisplayName
* TemplateId
* versionInfo

Note: These properties are used to aid in the import of the policy.

#### Get-EndpointSecurityTemplate Function
This function is used to get all Endpoint Security Templates available in the Intune service for your tenant.

```PowerShell
# Returns all Endpoint Security Templates configured in Intune
Get-EndpointSecurityTemplate
```

#### Add-EndpointSecurityPolicy Function
This function used to add an Endpoint Security policy to the Intune Service. It requires multiple parameters:

* TemplateId - Endpoint Security Template ID
* JSON - JSON data needs to be an input to the function so it can be passed to the service.

```PowerShell
Add-EndpointSecurityPolicy -TemplateId $TemplateId -JSON $JSON
```

### 4. EndpointSecurityTemplates_Get.ps1
This script gets all the Endpoint Security Templates from the Intune Service that you have authenticated with.

#### Get-EndpointSecurityTemplate Function
This function is used to get all Endpoint Security Templates available in the Intune service for your tenant.

```PowerShell
# Returns all Endpoint Security Templates configured in Intune
Get-EndpointSecurityTemplate
```
