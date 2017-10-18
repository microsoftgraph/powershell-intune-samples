# Admin Consent Script Samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

#### Admin Consent
When you first run any of the sample scripts against Microsoft Graph an Application is created in your tenant called "Microsoft Intune PowerShell". When a Global Admin of the tenant runs this script then permissions are set for the Global Admin only, it doesn't set delegated admin. To enable delegated admin functionality, i.e. allowing users who are not Global Admins the possibility to run Intune Graph scripts in the tenant, please execute the following script.

Note: Users who make use of the delegated admin actions will still require appropriate permissions to be granted to them by either being assigned to "Intune Service administrator" in AAD directory role (Limited Administrator) OR through the more granular Intune roles. If you assign a user to the "Intune Service Administrator" role then they have full permission to the Intune service, if this isn't required then leverage "Intune Roles" within the Intune console.

To view the Enterprise Application in the Azure Console navigate to the following path:

Azure Active Directory - Enterprise Applications - All Applications, and then locate Microsoft Intune PowerShell. If the application is present select the application and in the Security section select Permissions to see which permissions have been set. If no permissions are presented then run the following script to set delegated admin for the tenant.

The change to set admin consent is the additions of "prompt=admin_consent" to the following line.

```PowerShell
$authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId,"prompt=admin_consent").Result
```

#### 1. GA_AdminConsent_Set.ps1
The first time you run these scripts you will be asked to provide an account to authenticate with the service (This needs to be a Global Admin of the tenant):
```
Please specify your user principal name for Azure Authentication:
```
Once you have provided a user principal name a popup will open prompting for your password. After a successful authentication with Azure Active Directory the user token will last for an hour, once the hour expires within the PowerShell session you will be asked to re-authenticate.

As your running the script with Admin Consent for the first time against your tenant a popup will be presented stating:

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

Once its set the permissions for the application in Azure Active Directory will be populated.

Note: You only need to run this once against your tenant.

## Copyright
Copyright (c) 2017 Microsoft. All rights reserved.
