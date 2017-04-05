# Intune Graph Samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

These samples demonstrate typical Intune administrator or Microsoft partner actions for managing Intune resources.

The following samples are included in this repository:
- Manage Applications - iOS, Android, Web
- App Protection Policy - Creation, Get and Delete
- Company Portal Branding - Get and Set
- Compliance Policy - Add, Get and Delete
- Device Configuration - Add, Get and Delete
- Enrollment Restrictions - Get and Set
- Managed Devices - Get, Overview and Device Action
- Intune Roles (RBAC) - Add, Get and Delete
- Remote Action Audits - Get
- Terms and Conditions - Add, Get and Delete
- User Policy Report

The scripts are licensed "as-is." under the MIT License.

## Using the Intune Graph API
The Intune Graph API enables access to Intune information programmatically for your tenant, and the API performs the same Intune operations as those available through the Azure Portal.  

Intune provides data into the Microsoft Graph in the same way as other cloud services do, with rich entity information and relationship navigation.  Use Microsoft Graph to combine information from other services and Intune to build rich cross-service applications for IT professionals or end users.     

## Prerequisites
Use of these Microsoft Graph API Intune PowerShell samples requires the following:
* [Azure PowerShell command-line tools](https://azure.microsoft.com/en-us/downloads/) - Used to authenticate user credentials with Azure Active Directory
* An Intune tenant which supports the Azure Portal with a production or trial license (https://docs.microsoft.com/en-us/intune-azure/introduction/what-is-microsoft-intune)
* Using the Microsoft Graph APIs to configure Intune controls and policies requires an Intune license.
* An account with permissions to administer the Intune Service
* PowerShell v5.0 on Windows 10 x64 (PowerShell v4.0 is a minimum requirement for the scripts to function correctly)

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

#### 2. Authentication with Microsoft Graph
Once you have authenticated with Microsoft Graph and Azure Active Directory the user token will last for an hour from authentication, once the hour expires within the PowerShell session you will be asked to re-authenticate.

Within the Get-AuthToken function by default the authentication prompt is set to "Always" so that the login is always presented to the user.

```
$authResult = $authContext.AcquireToken($resourceAppIdURI,$clientId,$redirectUri, "Always")
```

To change the prompt behaviour please review [PromptBehavior Enumeration](https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx) documentation on MSDN.

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
Copyright (c) 2017 Microsoft. All rights reserved.
