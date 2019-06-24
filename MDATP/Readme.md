# Microsoft Defender ATP Scripts

This repository of PowerShell sample scripts can assist in configuring a Microsoft Defender ATP environment. 

The following scripts are included in this repository:
- Configure-MDATPIntuneSecAdminRole.ps1

The scripts are licensed "as-is." under the MIT License.

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

## Using the Intune Graph API
The Intune Graph API enables access to Intune information programmatically for your tenant, and the API performs the same Intune operations as those available through the Azure Portal.  

Intune provides data into the Microsoft Graph in the same way as other cloud services do, with rich entity information and relationship navigation.  Use Microsoft Graph to combine information from other services and Intune to build rich cross-service applications for IT professionals or end users.     

## Prerequisites
Use of these Microsoft Graph API Intune PowerShell samples requires the following:
* Install the AzureAD PowerShell module by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt
* An Intune tenant which supports the Azure Portal with a production or trial license (https://docs.microsoft.com/en-us/intune-azure/introduction/what-is-microsoft-intune)
* Using the Microsoft Graph APIs to configure Intune controls and policies requires an Intune license.
* An account with permissions to administer the Intune Service
* PowerShell v5.0 on Windows 10 x64 (PowerShell v4.0 is a minimum requirement for the scripts to function correctly)
* Note: For PowerShell 4.0 you will require the [PowershellGet Module for PS 4.0](https://www.microsoft.com/en-us/download/details.aspx?id=51451) to enable the usage of the Install-Module functionality
* First time usage of these scripts requires a Global Administrator of the Tenant to accept the permissions of the application

## Getting Started
After the prerequisites are installed or met, perform the following steps to use these scripts:

#### 1. Script usage

1. Download the contents of the repository to your local Windows machine
* Extract the files to a local folder (e.g. C:\IntuneGraphSamples)
* Run PowerShell x64 from the start menu
* Browse to the directory (e.g. cd C:\IntuneGraphSamples)
* For each Folder in the local repository you can browse to that directory and then run the script of your choice
* Example Application script usage:
  * To use the Manage Applications scripts, from C:\IntuneGraphSamples, run "cd .\Applications\"
  * Once in the folder run .\Application_MDM_Get.ps1 to get all MDM added applications
  This sequence of steps can be used for each folder....

#### 2. Authentication with Microsoft Graph
The first time you run these scripts you will be asked to provide an account to authenticate with the service:
```
Please specify your user principal name for Azure Authentication:
```
Once you have provided a user principal name a popup will open prompting for your password. After a successful authentication with Azure Active Directory the user token will last for an hour, once the hour expires within the PowerShell session you will be asked to re-authenticate.

If you are running the script for the first time against your tenant a popup will be presented stating:

```
Microsoft Intune PowerShell needs permission to:

* Sign you in and read your profile
* Read all groups
* Read directory data
* Read and write Microsoft Intune Device Configuration and Policies (preview)
* Read and write Microsoft Intune RBAC settings (preview)
* Perform user-impacting remote actions on Microsoft Intune devices (preview)
* Sign in as you
* Read and write Microsoft Intune devices (preview)
* Read and write all groups
* Read and write Microsoft Intune configuration (preview)
* Read and write Microsoft Intune apps (preview)
```

Note: If your user account is targeted for device based conditional access your device must be enrolled or compliant to pass authentication.

## Contributing

If you'd like to contribute to this sample, see CONTRIBUTING.MD.

This project has adopted the Microsoft Open Source Code of Conduct. For more information see the Code of Conduct FAQ or contact opencode@microsoft.com with any additional questions or comments.

## Questions and comments

We'd love to get your feedback about the Intune PowerShell sample. You can send your questions and suggestions to us in the Issues section of this repository.

Your feedback is important to us. Connect with us on Stack Overflow. Tag your questions with [MicrosoftGraph] and [intune].


## Additional resources
* [Microsoft Graph API documentation](https://developer.microsoft.com/en-us/graph/docs)
* [Microsoft Graph Portal](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [Microsoft code samples](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)

## Copyright
Copyright (c) 2019 Microsoft. All rights reserved.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
