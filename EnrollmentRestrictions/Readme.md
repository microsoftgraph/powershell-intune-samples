# Intune Device Enrollment Restrictions script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. DeviceEnrollmentRestrictions_Get.ps1
This script gets the device enrollment restrictions from the Intune Service that you have authenticated with.

#### Get-Organization Function
This function is used to get information about the tenant organization from the Intune Service.

```PowerShell
# Returns organization information configured in Intune
Get-Organization
```
#### Get-DeviceEnrollmentRestrictions Function
This function is used to return the device enrollment restrictions from the Intune Service.

It requires a single parameter as an input to the function which is the organization id from the Get-Organization function to pull data from the service.

```PowerShell
# Returns device enrollment restrictions configured in Intune
Get-DeviceEnrollmentRestrictions -id 928bf66b-df3a-460d-8203-70a3e4b0a067
```
### 2. DeviceEnrollmentRestrictions_Set.ps1
This script sets the device enrollment restrictions in the Intune Service that you have authenticated with. The settings created by the script are shown below in the JSON section below.

#### Set-DeviceEnrollmentRestrictions Function
This function is used to set the device enrollment restrictions in the Intune Service. It requires multiple parameter -id and -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Set-DeviceEnrollmentRestrictions -id 2981ad5f-d7c5-4422-834c-4381c3a33079 -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Set-DeviceEnrollmentRestrictions function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON file are shown below:

#### JSON

```JSON
{
    "defaultDeviceEnrollmentRestrictions":{
        "androidRestrictions":{
        "platformBlocked":false,
        "personalDeviceEnrollmentBlocked":false
        },
        "iosRestrictions":{
        "platformBlocked":false,
        "personalDeviceEnrollmentBlocked":false
        },
        "macRestrictions":{
        "platformBlocked":false,
        "personalDeviceEnrollmentBlocked":false
        },
        "windowsRestrictions":{
        "platformBlocked":false,
        "personalDeviceEnrollmentBlocked":false
        },
        "windowsMobileRestrictions":{
        "platformBlocked":false,
        "personalDeviceEnrollmentBlocked":false
        }
    }
}
```
