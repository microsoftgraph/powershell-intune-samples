# Intune Company Portal Branding script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. CompanyPortal_Get.ps1
This script gets all the company portal branding from the Intune Service that you have authenticated with.

#### Get-IntuneBrand Function
This function is used to return and company portal branding from the Intune Service.

```PowerShell
# Returns company portal branding configured in Intune
Get-IntuneBrand
```
### 2. CompanyPortal_Set_Brand.ps1
This script sets the company portal branding in the Intune Service that you have authenticated with. The branding created by the script are shown below in the JSON section below.

#### Set-IntuneBrand Function
This function is used to set the company portal branding in the Intune Service. It requires multiple parameter -id and -JSON as an input to the function to pass the JSON data to the service.

```
Set-IntuneBrand -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Set-IntuneBrand function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file are shown below:

#### JSON

```JSON
{
    "intuneBrand":{
    "displayName": "IT Company",
    "contactITName": "IT Admin",
    "contactITPhoneNumber": "01234567890",
    "contactITEmailAddress": "admin@itcompany.com",
    "contactITNotes": "some notes go here",
    "privacyUrl": "http://itcompany.com",
    "onlineSupportSiteUrl": "http://www.itcompany.com",
    "onlineSupportSiteName": "IT Company Website",
    "themeColor": {"r":0,"g":114,"b":198},
    "showLogo": true,
    "lightBackgroundLogo": {
        "type": "$iconType`;base",
        "value": "$base64icon"
          },
    "darkBackgroundLogo": {
        "type": "$iconType`;base",
        "value": "$base64icon"
          },
    "showNameNextToLogo": false,
    "@odata.type":"#microsoft.management.services.api.intuneBrand"
    }
}
```
### 3. CompanyPortal_Set_Default.ps1
This script sets the company portal branding to default values in the Intune Service that you have authenticated with. The branding created by the script is shown below in the JSON section.

#### JSON

```JSON
{

    "intuneBrand":{
    "displayName":null,
    "contactITName":null,
    "contactITPhoneNumber":null,
    "contactITEmailAddress":null,
    "contactITNotes":null,
    "privacyUrl":null,
    "onlineSupportSiteUrl":null,
    "onlineSupportSiteName":null,
    "themeColor":{"r":0,"g":114,"b":198},
    "showLogo":false,
    "showNameNextToLogo":false,
    "lightBackgroundLogo":null,
    "darkBackgroundLogo":null,
    "@odata.type":"#microsoft.management.services.api.intuneBrand"
    }

}
```
### 4. CompanyPortal_Export.ps1
This script gets Company portal branding from the Intune Service that you have authenticated with and exports the configuration to a JSON file.

#### Get-IntuneBrand Function
This function is used to return Company portal branding from the Intune Service.

```PowerShell
# Returns company portal branding configured in Intune
Get-IntuneBrand
```
#### Export-JSONData Function
This function is used to export Branding information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```

### 5. CompanyPortal_Import_FromJSON.ps1
This script imports from a JSON file company portal branding into the Intune Service that you have authenticated with.

When you run the script it will prompt for a path to a .json file, if the path is valid the Set-IntuneBrand function will be called.

```PowerShell
$ImportPath = Read-Host -Prompt "Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Branding\Branding.json"

# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"','')

if(!(Test-Path "$ImportPath")){

Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
Write-Host "Script can't continue..." -ForegroundColor Red
Write-Host
break

}
```

#### Set-IntuneBrand Function
This function is used to set the company portal branding in the Intune Service. It requires multiple parameter -id and -JSON as an input to the function to pass the JSON data to the service.

```
Set-IntuneBrand -JSON $JSON
```
