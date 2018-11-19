# Application Sync script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. Sync-AppleVPP.ps1
This script reads the Apple VPP tokens in your Intune tenant and synchronizes with the Apple VPP service. If there are multiple VPP tokens, you will be prompted to select which token you wish to synchronize. The script will not synchronize multiple tokens at once.

#### Get-VPPToken Function
This function is used to retrieve the VPP tokens from the Intune service
```PowerShell
# Returns Apple VPP tokens from the Intune Service
Get-VPPToken
```

#### Sync-AppleVPP Function
This function is used to synchronize with the Apple VPP server. The command requires the ID parameter to determine which VPP token to sync.
```PowerShell
# Synchronizes the selected token with the Apple VPP service
Sync-AppleVPP -id $id
```

### 2. ManagedGooglePlay_Sync.ps1
This script queries the Managed Google Play configuration in your Intune tenant. If a configuration is found, it synchronizes approved applications from the Managed Google Play Store to Intune.

#### Get-AndroidManagedStore Function
This function is used to query the Android Managed Store Account Enterprise settings in the Intune Service.
```PowerShell
# Returns the Managed Google Play configuration from Intune
Get-AndroidManagedStore
```

#### Sync-AndroidManagedStore Function
This function is used to initiate a synchronization with the Managed Google Play configuration in the Intune Service.
```PowerShell
# Initiates a Managed Google Play Sync in Intune
Sync-AndroidManagedStore
```
