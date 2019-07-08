# Intune App Configuration Policy Script Samples
This repository of PowerShell sample scripts show how to access Intune service resources. They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant. Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account.

Within this section there are the following scripts with the explanation of usage.

### 1.	AppConfigurationPolicy_Export.ps1
This script gets all App Configuration Policies in an Intune tenant and exports each policy to .json format in the directory of your choice. 

#### Get-ManagedAppAppConfigPolicy
This function is used to get app configuration policies for managed apps from the Graph API REST interface.
#### Get-ManagedDeviceAppConfigPolicy
This function is used to get app configuration policies for managed devices from the Graph API REST interface.
#### Get-AppBundleID
This function is used to get an app bundle ID from the Graph API REST interface
#### Export-JSONData
This function is used to export JSON data returned from Graph
### 2.	AppConfigurationPolicy_ImportFromJSON.ps1
This script imports an App Configuration Policy from a JSON file into the Intune Service you have authenticated with. 
When you run the script it will prompt for a path to a .json file.
#### Add-ManagedAppAppConfigPolicy
This function is used to add an app configuration policy for managed apps using the Graph API REST interface
#### Add-ManagedDeviceAppConfigPolicy
This function is used to add an app configuration policy for managed devices using the Graph API REST interface
#### Test-AppBundleId 
This function is used to test whether an app bundle ID is present in the client apps from the Graph API REST interface 
#### Test-AppPackageId 
This function is used to test whether an app package ID is present in the client apps from the Graph API REST interface
#### Test-JSON
This function is used to test if the JSON passed to a REST Post request is valid

