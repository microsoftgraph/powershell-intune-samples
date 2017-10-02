# Intune Application script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. Application_Android_Add_No_Icon.ps1
This script adds an Android application into the Intune Service that you have authenticated with. The application created by the script is shown below in the Android Application JSON section below.

#### Add-AndroidApplication Function
This function is used to add a compliance policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-AndroidApplication -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-AndroidApplication function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file is shown below:

#### Android Application JSON

```JSON
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Outlook",
  "description": "Microsoft Outlook",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.outlook&hl=en",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }

}
```
### 2. Application_Android_Add_With_Icon.ps1
This script adds an Android application into the Intune Service that you have authenticated with. The application created by the script is shown below in the Android Application JSON section below.

#### Add-AndroidApplication Function
This function is used to add a Web Application to the Intune Service. It supports multiple parameters -JSON and -IconURL as an input to the function to pass the JSON data to the service.

```
Add-AndroidApplication -JSON $JSON -IconURL "C:\IntuneIcons\Outlook.png"
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-AndroidApplication function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file is shown below:

#### Android Application JSON

```JSON
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Outlook",
  "description": "Microsoft Outlook",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  "largeIcon": {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.outlook&hl=en",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }

}
```

### 3. Application_Category_Add.ps1
This script gets adds an Application Category into the Intune Service that you have authenticated with.

#### Add-ApplicationCategory Function
This function is used to add an Application Category to the Intune Service. It supports a single parameter -AppCategoryName as an input to the function to pass the Category Name to the service.

```PowerShell
Add-ApplicationCategory -AppCategoryName "LOB Apps"
```
### 4. Application_Category_Get.ps1
This script gets all Application Categories configured in the Intune Service that you have authenticated with.

#### Get-ApplicationCategory Function
This function is used to get an Application Category from the Intune Service. It supports a single parameter -Name as an input to the function to pass the Category Name to the service.

```PowerShell
# Returns all Application Categories in the Intune Service
Get-ApplicationCategory

# Returns an Application by name which isn't an inbuilt application category
Get-ApplicationCategory -Name "LOB Apps 2" | Where-Object { $_.lastModifiedDateTime -ne "0001-01-01T00:00:00Z" }
```
### 5. Application_Category_Remove.ps1
This script removes an Application Category configured in the Intune Service that you have authenticated with.

#### Get-ApplicationCategory Function
This function is used to get an Application Category from the Intune Service. It supports a single parameter -Name as an input to the function to pass the Category Name to the service. There is a Where-Object filter used to show the category that isn't an inbuilt category as those can't be removed.

```PowerShell
# Returns all Application Categories in the Intune Service
Get-ApplicationCategory

# Returns an Application by name which isn't an inbuilt application category
Get-ApplicationCategory -Name "LOB Apps 2" | Where-Object { $_.lastModifiedDateTime -ne "0001-01-01T00:00:00Z" }
```
#### Remove-ApplicationCategory Function
This function is used to remove an Application Category from the Intune Service. It supports a single parameter -Name as an input to the function to pass the Category Name to the service.

```PowerShell
# Returns an Application by name which isn't an inbuilt application category
$App = Get-ApplicationCategory -Name "LOB Apps 2" | Where-Object { $_.lastModifiedDateTime -ne "0001-01-01T00:00:00Z" }

# Removes an Application category from the Intune Service
Remove-ApplicationCategory -id $App.id
```

### 6. Application_iOS_Add.ps1
This script adds an iOS application from the itunes store to the Intune Service that you have authenticated with.

To query the itunes store the following resource is used to complete the web search. https://affiliate.itunes.apple.com/resources/documentation/itunes-store-web-service-search-api/

#### Get-itunesApplication Function
This function is used to query the itunes REST API to search the itunes store for an application. There is a single required field which is the -SearchString parameter which is used to search the store for an application or company with that name. There is also a -Limit parameter which is used to limit the amount of application which are returned.

```PowerShell
# Returns applications in the itunes store with the Microsoft Corporation in the name or company and is limited to 50 responses.
Get-itunesApplication -SearchString "Microsoft Corporation" -Limit 50
```

#### Add-iOSApplication Function
This function is used to add an iOS application from the itunes store into the Intune Service. It has a required parameter of -itunesApp which is the JSON data returned from the itunes store.

```PowerShell
Add-iOSApplication -itunesApp $iApp
```
The script shows a sample of how you can specify the applications you want to add in specifically rather than adding all applications with "Microsoft Corporation" in the name. To specify a list the following PowerShell is used to create an array of application names that you wish to add. If any of these names are found within the returned data of the "Get-itunesApplication" function then they will be added in specifically.

```PowerShell
#region Office Example
$Applications = 'Microsoft Outlook','Microsoft Excel','OneDrive','Microsoft Word',"Microsoft PowerPoint"
#endregion
```
If you no applications are specified then all application JSON found in returned data will be added to the Intune Service.

### 7. Application_iOS_Add_Assign.ps1
This script adds and Assigns an iOS application from the itunes store to the Intune Service that you have authenticated with.

To query the itunes store the following resource is used to complete the web search. https://affiliate.itunes.apple.com/resources/documentation/itunes-store-web-service-search-api/

#### Get-itunesApplication Function
This function is used to query the itunes REST API to search the itunes store for an application. There is a single required field which is the -SearchString parameter which is used to search the store for an application or company with that name. There is also a -Limit parameter which is used to limit the amount of application which are returned.

```PowerShell
# Returns applications in the itunes store with the Microsoft Corporation in the name or company and is limited to 50 responses.
Get-itunesApplication -SearchString "Microsoft Corporation" -Limit 50
```

#### Add-iOSApplication Function
This function is used to add an iOS application from the itunes store into the Intune Service. It has a required parameter of -itunesApp which is the JSON data returned from the itunes store.

```PowerShell
Add-iOSApplication -itunesApp $iApp
```
The script shows a sample of how you can specify the applications you want to add in specifically rather than adding all applications with "Microsoft Corporation" in the name. To specify a list the following PowerShell is used to create an array of application names that you wish to add. If any of these names are found within the returned data of the "Get-itunesApplication" function then they will be added in specifically.

```PowerShell
#region Office Example
$Applications = 'Microsoft Outlook','Microsoft Excel','OneDrive','Microsoft Word',"Microsoft PowerPoint"
#endregion
```
If you no applications are specified then all application JSON found in returned data will be added to the Intune Service.

#### Add-ApplicationAssignment Function
This function is used to add an application assignment to a specified application added to the Intune Service. It has the following required parameters -ApplicationId, -TargetGroupId and -InstallIntent.

+ ApplicationId - The ID of the application in the Intune Service
+ TargetGroupId - The AAD Group ID (guid) where the application will be assigned
+ InstallIntent - The intent of installation e.g. Available, Required, Uninstall

```PowerShell
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
```

#### Get-AADGroup Function
This function is used to get an AAD Group by -GroupName to be used to assign an application to.

```PowerShell
# Setting application AAD Group to assign application

$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where applications will be assigned"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host
```

### 8. Application_MAM_Get.ps1
This script gets all MAM applications configured in the Intune Service that you have authenticated with.

#### Get-IntuneMAMApplication Function
This function is used to get all Managed applications from the Intune Service and has a filter to only show applications where the odata.type contains "managed".

```PowerShell
# Returns all MAM applications in the Intune Service
Get-IntuneMAMApplication

# Returns all MAM application and selects the displayName, id and type
Get-IntuneMAMApplication | select displayName,id,'@odata.type' | sort displayName
```

### 9. Application_MDM_Get.ps1
This script gets all MDM applications configured in the Intune Service that you have authenticated with.

#### Get-IntuneApplication Function
This function is used to get all MDM applications from the Intune Service and has a filter to only show applications where the odata.type doesn't contain "managed" or "iosVppApp". It supports a single parameter -Name as an input to the function which can be used to filter on a single application.

```PowerShell
# Returns all MDM applications in the Intune Service
Get-IntuneApplication

# Returns an application by Name in the Intune Service
Get-IntuneApplication -Name "Microsoft Excel"

# Returns all MDM application and selects the displayName, id and type
Get-IntuneApplication | select displayName,id,'@odata.type' | sort displayName
```
Once the data has been returned then the "Get-ApplicationAssignment" function is used to pull assignment information and install intent for the application.

#### Get-ApplicationAssignment Function
This function is used to get an application assignment from the Intune Service. It requires a single parameter -ApplicationId of the application you want to check the group assignment and install intention.

```PowerShell
# Returns all MDM applications in the Intune Service
Get-ApplicationAssignment -ApplicationId 506c3995-251c-438b-8c68-174fae30e83a
```

### 10. Application_MDM_Remove.ps1
This script adds an iOS application from the itunes store to the Intune Service that you have authenticated with.

#### Get-IntuneApplication Function
This function is used to get all MDM applications from the Intune Service and has a filter to only show applications where the odata.type doesn't contain "managed" or "iosVppApp". It supports a single parameter -Name as an input to the function which can be used to filter on a single application.

```PowerShell
# Returns all MDM applications in the Intune Service
Get-IntuneApplication

# Returns an application by Name in the Intune Service
Get-IntuneApplication -Name "Microsoft Excel"

# Returns all MDM application and selects the displayName, id and type
Get-IntuneApplication | select displayName,id,'@odata.type' | sort displayName
```

#### Remove-IntuneApplication Function
This function is used to remove an MDM application from the Intune Service. It requires a single parameter -Id as an input to the function.

```PowerShell
# Returns an application by Name in the Intune Service
$App = Get-IntuneApplication -Name "Microsoft Excel"

# Remove the application from the intune service if its found
Remove-IntuneApplication -id $App.id
```

### 11. Application_Web_Add_No_Icon.ps1
This script adds a Web application into the Intune Service that you have authenticated with. The application created by the script is shown below in the Web Application JSON section below.

#### Add-WebApplication Function
This function is used to add a Web Application to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-WebApplication -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-WebApplication function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file is shown below:

#### Web Application JSON

```JSON
{
    "@odata.type":"#microsoft.graph.webApp",
    "displayName":"Bing Web Search",
    "description":"Bing Web Search",
    "publisher":"Intune Admin",
    "isFeatured":false,
    "appUrl":"https://www.bing.com",
    "useManagedBrowser":false
}
```
### 12. Application_Web_Add_With_Icon.ps1
This script adds a Web application into the Intune Service that you have authenticated with. The application created by the script is shown below in the Web Application JSON section below.

#### Add-WebApplication Function
This function is used to add a Web Application to the Intune Service. It supports multiple parameters -JSON and -IconURL as an input to the function to pass the JSON data to the service.

```PowerShell
Add-WebApplication -JSON $JSON -IconURL "C:\IntuneIcons\bing.png"
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-WebApplication function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file is shown below:

#### Web Application JSON

```JSON
{
    "@odata.type":"#microsoft.graph.webApp",
    "displayName":"Bing Web Search",
    "description":"Bing Web Search",
    "publisher":"Intune Admin",
    "isFeatured":false,
    "appUrl":"https://www.bing.com",
    "useManagedBrowser":false,
    "largeIcon": {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
    }
}
```
