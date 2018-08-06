# Intune Device Configuration Policy script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. DeviceConfiguration_Add.ps1
This script adds an iOS and Android device configuration policy into the Intune Service that you have authenticated with. The policies created by the script are shown below in the Android and iOS JSON sections below.

#### Add-DeviceConfigurationPolicy Function
This function is used to add a device configuration policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-DeviceConfigurationPolicy -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-DeviceCompliancePolicy function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON files are shown below:

#### Android JSON

```JSON
{
    "@odata.type": "#microsoft.graph.androidGeneralDeviceConfiguration",
    "description": "Android Device Restriction Policy",
    "displayName": "Android Device Restriction Policy",
    "appsBlockClipboardSharing": false,
    "appsBlockCopyPaste": false,
    "appsBlockYouTube": false,
    "bluetoothBlocked": false,
    "cameraBlocked": false,
    "cellularBlockDataRoaming": true,
    "cellularBlockMessaging": false,
    "cellularBlockVoiceRoaming": false,
    "cellularBlockWiFiTethering": false,
    "compliantAppsList": [],
    "compliantAppListType": "none",
    "diagnosticDataBlockSubmission": false,
    "locationServicesBlocked": false,
    "googleAccountBlockAutoSync": false,
    "googlePlayStoreBlocked": false,
    "kioskModeBlockSleepButton": false,
    "kioskModeBlockVolumeButtons": false,
    "kioskModeManagedAppId": null,
    "nfcBlocked": false,
    "passwordBlockFingerprintUnlock": true,
    "passwordBlockTrustAgents": false,
    "passwordExpirationDays": null,
    "passwordMinimumLength": 4,
    "passwordMinutesOfInactivityBeforeScreenTimeout": null,
    "passwordPreviousPasswordBlockCount": null,
    "passwordSignInFailureCountBeforeFactoryReset": null,
    "passwordRequiredType": "deviceDefault",
    "passwordRequired": true,
    "powerOffBlocked": false,
    "factoryResetBlocked": false,
    "screenCaptureBlocked": false,
    "deviceSharingBlocked": false,
    "storageBlockGoogleBackup": true,
    "storageBlockRemovableStorage": false,
    "storageRequireDeviceEncryption": true,
    "storageRequireRemovableStorageEncryption": true,
    "voiceAssistantBlocked": false,
    "voiceDialingBlocked": false,
    "webBrowserAllowPopups": false,
    "webBrowserBlockAutofill": false,
    "webBrowserBlockJavaScript": false,
    "webBrowserBlocked": false,
    "webBrowserCookieSettings": "browserDefault",
    "wiFiBlocked": false
}
```

#### iOS JSON

```JSON
{
    "@odata.type": "#microsoft.graph.iosGeneralDeviceConfiguration",
    "description": "iOS Device Restriction Policy",
    "displayName": "iOS Device Restriction Policy",
    "accountBlockModification": false,
    "activationLockAllowWhenSupervised": false,
    "airDropBlocked": false,
    "airDropForceUnmanagedDropTarget": false,
    "airPlayForcePairingPasswordForOutgoingRequests": false,
    "appleWatchBlockPairing": false,
    "appleWatchForceWristDetection": false,
    "appleNewsBlocked": false,
    "appsVisibilityList": [],
    "appsVisibilityListType": "none",
    "appStoreBlockAutomaticDownloads": false,
    "appStoreBlocked": false,
    "appStoreBlockInAppPurchases": false,
    "appStoreBlockUIAppInstallation": false,
    "appStoreRequirePassword": false,
    "bluetoothBlockModification": false,
    "cameraBlocked": false,
    "cellularBlockDataRoaming": false,
    "cellularBlockGlobalBackgroundFetchWhileRoaming": false,
    "cellularBlockPerAppDataModification": false,
    "cellularBlockVoiceRoaming": false,
    "certificatesBlockUntrustedTlsCertificates": false,
    "classroomAppBlockRemoteScreenObservation": false,
    "compliantAppsList": [],
    "compliantAppListType": "none",
    "configurationProfileBlockChanges": false,
    "definitionLookupBlocked": false,
    "deviceBlockEnableRestrictions": false,
    "deviceBlockEraseContentAndSettings": false,
    "deviceBlockNameModification": false,
    "diagnosticDataBlockSubmission": false,
    "diagnosticDataBlockSubmissionModification": false,
    "documentsBlockManagedDocumentsInUnmanagedApps": false,
    "documentsBlockUnmanagedDocumentsInManagedApps": false,
    "emailInDomainSuffixes": [],
    "enterpriseAppBlockTrust": false,
    "enterpriseAppBlockTrustModification": false,
    "faceTimeBlocked": false,
    "findMyFriendsBlocked": false,
    "gamingBlockGameCenterFriends": true,
    "gamingBlockMultiplayer": false,
    "gameCenterBlocked": false,
    "hostPairingBlocked": false,
    "iBooksStoreBlocked": false,
    "iBooksStoreBlockErotica": false,
    "iCloudBlockActivityContinuation": false,
    "iCloudBlockBackup": true,
    "iCloudBlockDocumentSync": true,
    "iCloudBlockManagedAppsSync": false,
    "iCloudBlockPhotoLibrary": false,
    "iCloudBlockPhotoStreamSync": true,
    "iCloudBlockSharedPhotoStream": false,
    "iCloudRequireEncryptedBackup": false,
    "iTunesBlockExplicitContent": false,
    "iTunesBlockMusicService": false,
    "iTunesBlockRadio": false,
    "keyboardBlockAutoCorrect": false,
    "keyboardBlockPredictive": false,
    "keyboardBlockShortcuts": false,
    "keyboardBlockSpellCheck": false,
    "kioskModeAllowAssistiveSpeak": false,
    "kioskModeAllowAssistiveTouchSettings": false,
    "kioskModeAllowAutoLock": false,
    "kioskModeAllowColorInversionSettings": false,
    "kioskModeAllowRingerSwitch": false,
    "kioskModeAllowScreenRotation": false,
    "kioskModeAllowSleepButton": false,
    "kioskModeAllowTouchscreen": false,
    "kioskModeAllowVoiceOverSettings": false,
    "kioskModeAllowVolumeButtons": false,
    "kioskModeAllowZoomSettings": false,
    "kioskModeAppStoreUrl": null,
    "kioskModeRequireAssistiveTouch": false,
    "kioskModeRequireColorInversion": false,
    "kioskModeRequireMonoAudio": false,
    "kioskModeRequireVoiceOver": false,
    "kioskModeRequireZoom": false,
    "kioskModeManagedAppId": null,
    "lockScreenBlockControlCenter": false,
    "lockScreenBlockNotificationView": false,
    "lockScreenBlockPassbook": false,
    "lockScreenBlockTodayView": false,
    "mediaContentRatingAustralia": null,
    "mediaContentRatingCanada": null,
    "mediaContentRatingFrance": null,
    "mediaContentRatingGermany": null,
    "mediaContentRatingIreland": null,
    "mediaContentRatingJapan": null,
    "mediaContentRatingNewZealand": null,
    "mediaContentRatingUnitedKingdom": null,
    "mediaContentRatingUnitedStates": null,
    "mediaContentRatingApps": "allAllowed",
    "messagesBlocked": false,
    "notificationsBlockSettingsModification": false,
    "passcodeBlockFingerprintUnlock": false,
    "passcodeBlockModification": false,
    "passcodeBlockSimple": true,
    "passcodeExpirationDays": null,
    "passcodeMinimumLength": 4,
    "passcodeMinutesOfInactivityBeforeLock": null,
    "passcodeMinutesOfInactivityBeforeScreenTimeout": null,
    "passcodeMinimumCharacterSetCount": null,
    "passcodePreviousPasscodeBlockCount": null,
    "passcodeSignInFailureCountBeforeWipe": null,
    "passcodeRequiredType": "deviceDefault",
    "passcodeRequired": true,
    "podcastsBlocked": false,
    "safariBlockAutofill": false,
    "safariBlockJavaScript": false,
    "safariBlockPopups": false,
    "safariBlocked": false,
    "safariCookieSettings": "browserDefault",
    "safariManagedDomains": [],
    "safariPasswordAutoFillDomains": [],
    "safariRequireFraudWarning": false,
    "screenCaptureBlocked": false,
    "siriBlocked": false,
    "siriBlockedWhenLocked": false,
    "siriBlockUserGeneratedContent": false,
    "siriRequireProfanityFilter": false,
    "spotlightBlockInternetResults": false,
    "voiceDialingBlocked": false,
    "wallpaperBlockModification": false
}
```
### 2. DeviceConfiguration_Add_Assign.ps1
This script adds and Assigns an iOS and Android device configuration policy into the Intune Service that you have authenticated with. The policies created by the script are shown below in the Android and iOS JSON sections below.

#### Add-DeviceConfigurationPolicy Function
This function is used to add a device configuration policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-DeviceConfigurationPolicy -JSON $JSON
```

#### Add-DeviceConfigurationPolicyAssignment Function
This function is used to assign a policy to an AAD Group. This function has two required parameters.

+ ConfigurationPolicyId - The policy ID defined in the Intune Service
+ TargetGroupId - The AAD Group ID where the policy should be assigned

```PowerShell
Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_Android.id -TargetGroupId $TargetGroupId
```

#### Get-AADGroup Function
This function is used to get an AAD Group by -GroupName to be used to assign to the policy.

```PowerShell
$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name for Policy assignment"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host
```
### 3. DeviceConfiguration_Export.ps1
This script gets all the device configuration policies from the Intune Service that you have authenticated with. The script will then export the policy to .json format in the directory of your choice.

```PowerShell
$ExportPath = Read-Host -Prompt "Please specify a path to export the policy data to e.g. C:\IntuneOutput"

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

#### Get-DeviceConfigurationPolicy Function
This function is used to get all device configuration policies from the Intune Service.

It supports a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns all device configuration policies configured in Intune
Get-DeviceConfigurationPolicy

# Returns a device configuration policy that contains the Name configured in Intune
Get-DeviceConfigurationPolicy -Name "Android"

```

#### Export-JSONData Function
This function is used to export the policy information. It has two required parameters -JSON and -ExportPath.

+ JSON - The JSON data
+ ExportPath - The path where the .json should be exported to

```PowerShell
Export-JSONData -JSON $JSON -ExportPath "$ExportPath"
```


### 4. DeviceConfiguration_Get.ps1
This script gets all the device configuration policies from the Intune Service that you have authenticated with.

#### Get-DeviceConfigurationPolicy Function
This function is used to get all device configuration policies from the Intune Service.

It supports a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns all device configuration policies configured in Intune
Get-DeviceConfigurationPolicy

# Returns a device configuration policy that contains the Name configured in Intune
Get-DeviceConfigurationPolicy -Name "Android"

```

### 5. DeviceConfiguration_Import_FromJSON.ps1
This script imports from a JSON file a device configuration policy into the Intune Service that you have authenticated with.

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

#### Add-DeviceConfigurationPolicy Function
This function is used to add a device configuration policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```PowerShell
Add-DeviceConfigurationPolicy -JSON $JSON
```


### 6. DeviceConfiguration_Remove.ps1
This script removes a device configuration policy configured in the Intune Service that you have authenticated with.

#### Remove-DeviceConfigurationPolicy Function
This function is used to remove a device configuration policy from the Intune Service.

It supports a single parameter -id as an input to the function to specify the id of the compliance policy that you wish to remove. The script will get a policy of choice via the -Name parameter and then remove it if it's valid.

```PowerShell
# Removes an individual device configuration policy from the Intune Service
$CP = Get-DeviceConfigurationPolicy -Name "Test Policy"

Remove-DeviceConfigurationPolicy -id $CP.id
```

### 7. DeviceManagementScripts_Get.ps1
This script gets all device management scripts configured in the Intune Service that you have authenticated with.

#### Get-DeviceManagementScripts Function
This function is used to get all device management scripts from the Intune Service.

It supports a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns all device management scripts configured in Intune
Get-DeviceManagementScripts

# Returns a device management script that contains the Script Id configured in Intune
Get-DeviceManagementScripts -ScriptId "$ScriptId"

```

### 8. DeviceManagementScript_Add.ps1
This script adds a device management script into the Intune Service that you have authenticated with.

#### Add-DeviceManagementScript Function
This function is used to add a device management script to the Intune Service. It supports both adding scripts from a local file path or a URL. It supports three parameters -File where you define the path or URL to a file. -Description to define the description field of the script in Intune. -URL which is a switch to specify that the -File parameter is a URL.

```PowerShell
Add-DeviceManagementScript -File "C:\Scripts\Spript.ps1" -Description "Script"
Add-DeviceManagementScript -File "https://pathtourl/test-script.ps1" -URL -Description "Test script"
```

### 9. DeviceManagementScript_Add_Assign.ps1
This script adds and assigns a device management script into the Intune Service that you have authenticated with.

#### Add-DeviceManagementScriptAssignment Function
This function is used to assign a device management script to an AAD Group. This function has two required parameters.

+ ScriptId - The script ID defined in the Intune Service
+ TargetGroupId - The AAD Group ID where the policy should be assigned

```PowerShell
Add-DeviceManagementScriptAssignment -ScriptId $Create_Local_Script.id -TargetGroupId $TargetGroupId
```