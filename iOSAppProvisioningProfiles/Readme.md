# iOS App Provisioning Profile Script Samples

 

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

 

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

 

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

 

Within this section there are the following scripts with the explanation of usage.

### iOSAppProvisioningProfile_Analysis.ps1
This script gets the iOS Provisioning Profiles in an Intune tenant and outputs the expiry information from the mobileprovision file.

#### Get-AADGroup Function
This function is used to get AAD Groups from the Graph API REST interface

#### Get-iOSAppProvisioningProfile
This function is used to get iOS Provisioning Profile expiry information from the plist file uploaded to Intune.

