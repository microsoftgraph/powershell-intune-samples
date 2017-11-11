# Intune Device Enrollment Restrictions script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. DeviceEnrollmentRestrictions_Get.ps1
This script gets the device enrollment restrictions from the Intune Service that you have authenticated with.

#### Get-DeviceEnrollmentConfigurations Function
This function is used to return the device enrollment configuration from the Intune Service.

```PowerShell
# Returns all device enrollment configurations configured in Intune
Get-DeviceEnrollmentConfigurations
```
### 2. DeviceEnrollmentRestrictions_Set.ps1
This script sets the device enrollment restrictions in the Intune Service that you have authenticated with. The settings created by the script are shown below in the JSON section below.

#### Get-DeviceEnrollmentConfigurations Function
This function is used to return the device enrollment configuration from the Intune Service.

It requires a filter on the returned data to get the DefaultPlatformRestrictions which is done by using the PowerShell Where-Object filter.

```PowerShell
# Returns all device enrollment configurations configured in Intune and then filters on Default Platform Restrictions
$DeviceEnrollmentConfigurations = Get-DeviceEnrollmentConfigurations

$PlatformRestrictions = ($DeviceEnrollmentConfigurations | Where-Object { ($_.id).contains("DefaultPlatformRestrictions") }).id
```

#### Set-DeviceEnrollmentRestrictions Function
This function is used to set the device enrollment restrictions in the Intune Service. It requires multiple parameter -DEC_Id and -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Set-DeviceEnrollmentConfiguration -DEC_Id $PlatformRestrictions -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Set-DeviceEnrollmentConfiguration function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file are shown below:

#### JSON

```JSON
{
    "@odata.type":"#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
    "displayName":"All Users",
    "description":"This is the default Device Type Restriction applied with the lowest priority to all users regardless of group membership.",

    "androidRestriction":{
    "platformBlocked":false,
    "personalDeviceEnrollmentBlocked":false,
    "osMinimumVersion":"",
    "osMaximumVersion":""
    },
    "androidForWorkRestriction":{
    "platformBlocked":false,
    "personalDeviceEnrollmentBlocked":false,
    "osMinimumVersion":null,
    "osMaximumVersion":null
    },
    "iosRestriction":{
    "platformBlocked":false,
    "personalDeviceEnrollmentBlocked":false,
    "osMinimumVersion":"",
    "osMaximumVersion":""
    },
    "macRestriction":{
    "platformBlocked":false,
    "personalDeviceEnrollmentBlocked":false,
    "osMinimumVersion":null,
    "osMaximumVersion":null
    },
    "windowsRestriction":{
    "platformBlocked":false,
    "personalDeviceEnrollmentBlocked":false,
    "osMinimumVersion":"",
    "osMaximumVersion":""
    },
    "windowsMobileRestriction":{
    "platformBlocked":false,
    "personalDeviceEnrollmentBlocked":false,
    "osMinimumVersion":"",
    "osMaximumVersion":""
    }

}
```
