# Intune Application script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://docs.microsoft.com/en-us/graph/api/resources/intune-graph-overview?view=graph-rest-1.0).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. Application_Android_Add_No_Icon.ps1
This script adds an Android application into the Intune Service that you have authenticated with. The application created by the script is shown below in the Android Application JSON section below.

#### Add-AndroidApplication Function
This function is used to add an Android Application to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

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
This function is used to add an Android Application to the Intune Service. It supports multiple parameters -JSON and -IconURL as an input to the function to pass the JSON data to the service.

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
### 8. Application_MacOSOffice365_Add.ps1
This script adds a MacOS Office 365 application to the Intune Service that you have authenticated with.

#### Add-MDMApplication Function
This function is used to add an MDM Application to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-MDMApplication -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-MDMApplication function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file is shown below:

#### MacOS Office 365 Application JSON

```JSON
{
  "@odata.type": "#microsoft.graph.macOSOfficeSuiteApp",
  "description": "MacOS Office 365",
  "developer": "Microsoft",
  "displayName": "Mac Office 365",
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "notes": "",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "publisher": "Microsoft"
}
```

### 9. Application_MacOSOffice365_Add_Assign.ps1
This script adds and Assigns a MacOS Office 365 application to the Intune Service that you have authenticated with.

#### Add-MDMApplication Function
This function is used to add an MDM Application to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-MDMApplication -JSON $JSON
```
#### Test-JSON Function
This function is used to test if the JSON passed to the Add-MDMApplication function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file is shown below:

#### MacOS Office 365 Application JSON

```JSON
{
  "@odata.type": "#microsoft.graph.macOSOfficeSuiteApp",
  "description": "MacOS Office 365 - Assigned",
  "developer": "Microsoft",
  "displayName": "Mac Office 365 - Assigned",
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "notes": "",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "publisher": "Microsoft"
}
```

#### Add-ApplicationAssignment Function
This function is used to add an application assignment to a specified application added to the Intune Service. It has the following required parameters -ApplicationId, -TargetGroupId and -InstallIntent.

+ ApplicationId - The ID of the application in the Intune Service
+ TargetGroupId - The AAD Group ID (guid) where the application will be assigned
+ InstallIntent - The intent of installation e.g. Available, Required, Uninstall

```PowerShell
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
```

### 10. Application_MAM_Get.ps1
This script gets all MAM applications configured in the Intune Service that you have authenticated with.

#### Get-IntuneMAMApplication Function
This function is used to get all Managed applications from the Intune Service and has a filter to only show applications where the odata.type contains "managed".

```PowerShell
# Returns all MAM applications in the Intune Service
Get-IntuneMAMApplication

# Returns all MAM application and selects the displayName, id and type
Get-IntuneMAMApplication | select displayName,id,'@odata.type' | sort displayName
```

### 11. Application_MDM_Get.ps1
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

### 12. Application_MDM_Remove.ps1
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

### 13. Application_Office365_Add.ps1
This script adds a Windows 10 Office 365 application to the Intune Service that you have authenticated with.

#### Add-MDMApplication Function
This function is used to add an MDM Application to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-MDMApplication -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-MDMApplication function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file is shown below:

#### Windows 10 Office 365 Application JSON

```JSON
{
  "@odata.type": "#microsoft.graph.officeSuiteApp",
  "autoAcceptEula": true,
  "description": "Office 365 ProPlus",
  "developer": "Microsoft",
  "displayName": "Office 365 ProPlus",
  "excludedApps": {
    "groove": true,
    "infoPath": true,
    "sharePointDesigner": true
  },
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "localesToInstall": [
    "en-us"
  ],
  "notes": "",
  "officePlatformArchitecture": "x86",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "productIds": [
    "o365ProPlusRetail",
    "projectProRetail",
    "visioProRetail"
  ],
  "publisher": "Microsoft",
  "updateChannel": "firstReleaseCurrent",
  "useSharedComputerActivation": false
}
```

### 14. Application_Office365_Add_Assign.ps1
This script adds and Assigns a Windows 10 Office 365 application to the Intune Service that you have authenticated with.

#### Add-MDMApplication Function
This function is used to add an MDM Application to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-MDMApplication -JSON $JSON
```
#### Test-JSON Function
This function is used to test if the JSON passed to the Add-MDMApplication function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file is shown below:

#### Windows 10 Office 365 Application JSON

```JSON
{
  "@odata.type": "#microsoft.graph.officeSuiteApp",
  "autoAcceptEula": true,
  "description": "Office 365 ProPlus - Assigned",
  "developer": "Microsoft",
  "displayName": "Office 365 ProPlus - Assigned",
  "excludedApps": {
    "groove": true,
    "infoPath": true,
    "sharePointDesigner": true
  },
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "localesToInstall": [
    "en-us"
  ],
  "notes": "",
  "officePlatformArchitecture": "x86",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "productIds": [
    "o365ProPlusRetail",
    "projectProRetail",
    "visioProRetail"
  ],
  "publisher": "Microsoft",
  "updateChannel": "firstReleaseCurrent",
  "useSharedComputerActivation": false
}
```

#### Add-ApplicationAssignment Function
This function is used to add an application assignment to a specified application added to the Intune Service. It has the following required parameters -ApplicationId, -TargetGroupId and -InstallIntent.

+ ApplicationId - The ID of the application in the Intune Service
+ TargetGroupId - The AAD Group ID (guid) where the application will be assigned
+ InstallIntent - The intent of installation e.g. Available, Required, Uninstall

```PowerShell
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
```

### 15. Application_Web_Add_No_Icon.ps1
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
### 16. Application_Web_Add_With_Icon.ps1
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
### 17. Application_MDM_Export.ps1
This script gets all the MDM Configuration Applications from the Intune Service that you have authenticated with. The script will then export the applications to .json format in the directory of your choice.

```PowerShell
$ExportPath = Read-Host -Prompt "Please specify a path to export the application data to e.g. C:\IntuneOutput"

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

#### Get-IntuneApplication Function
This function is used to get all MDM applications from the Intune Service. It supports a single parameter -Name as an input to the function which can be used to filter on a single application.

```PowerShell
# Returns all MDM applications in the Intune Service
Get-IntuneApplication

# Returns an application by Name in the Intune Service
Get-IntuneApplication -Name "Microsoft Excel"

# Returns all MDM application and selects the displayName, id and type
Get-IntuneApplication | select displayName,id,'@odata.type' | sort displayName
```

#### Export-JSONData Function
This function is used to export the MDM Application information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```

### 18. Application_MDM_Import_FromJSON.ps1
This script imports from a JSON file an MDM configured application into the Intune Service that you have authenticated with.

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

#### Add-MDMApplication Function
This function is used to add an MDM Application to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-MDMApplication -JSON $JSON
```

### 19. Application_InstallStatus.ps1
This script gets the installation statistics for an application in the Intune Service that you have authenticated with.

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

#### Get-InstallStatusForApp
This function will get all of the installation stats for an application, given the applications ID. We can get the application's ID with the "Application_MDM_Get.ps1" script and the Get-IntuneApplication function.

````PowerShell
# Sample
Get-InstallaStatusForApp -AppId 1111-22222-33333-44444-55555

$Application = Get-IntuneApplication -Name "Microsoft Teams"
Get-InstallaStatusForApp -AppId $Application.id
```

