# Intune Line of Business App Upload – PowerShell Script readme and guide

Documentation for Intune and Microsoft Graph can be found here Intune Graph Documentation: https://developer.microsoft.com/en-us/graph/docs/concepts/overview.

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account.
## Introduction
The Microsoft Graph API for Intune provides the same facilities as does the Intune user interface so, automating manual tasks is a relatively straightforward programming process. In the case of a line of business (LOB) application, there are several additional steps required to complete the upload of the application file. This readme provides an overview and step-by-step guidance for uploading your line of business applications to Intune.

## 1. Application_LOB_Add.ps1
The following script sample provides the ability to upload an iOS or Android LOB application to the Intune Service.

### Prerequisites
+ Dependent PowerShell module (Azure AD)
https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0
+	For Android: Android Studio from https://developer.android.com/studio/index.html
+	Application metadata for iOS and Android applications
  +	Android – PackageID, IdentityVersion
  +	iOS – BundleID, IdentityVersion, ExpirationDateTime

#### Flow of the process
1.	Identify the key metadata required to create the application.
  + Android data comes specified on the command line or from the Android SDK
  + iOS data comes specified on the command line
  +	MSI data comes from using .NET to query the MSI directly
2.	Submit information in request body in JSON format and POST to new LOB App
3.	Create a content version for the LOB application and POST to LOB App
  +	Create a new file entry in the Content Version
  +	Wait for File entry  SAS URI in the service to be created and ready
  +	LOB app ready is now for content.
4.	Encrypt the file for upload and call the upload
5.	Upload to Azure Storage
6.	Commit the file to the reserved LOB app & version

### Using the Intune Graph API
Following the process flow in the preceding section, we’ll use as example, the UploadAndroidLob function for uploading an Android Line of Business (LOB) App to Intune. LOB is a generalized naming for your custom app. We recommend that you open the file containing the script with an editor that supports PowerShell. This will ease your reading of the elements of the script. Visual Studio Code is a good example of such an editor.
 
#### REST Operations
The primary REST operations used by the PowerShell script make use of methods defined for the Intune Graph API resource deviceAppManagment and executed via the PowerShell using the cmdlet Invoke-RestMethod.
For this explanation, the REST calls that are constructed by the script are expanded for your orientation.
<b>1.</b> Create LOB Application in the Intune Service
This is completed by passing application metadata in JSON format and completing a POST to the service. The POST URI is:

```
POST - https://graph.microsoft.com/beta/deviceAppManagement/mobileApps
```

The JSON metadata is constructed from the metadata of the file (IPA, APK, MSI).

#### Sample Android JSON

```
{

    "owner":  "",
    "fileName":  "A_Online_Radio_1.0.5.4.apk",
    "description":  "A Online Radio 1.0.5.4",
    "categories": [

                   ],
    "displayName":  "A_Online_Radio_1.0.5.4.apk",
    "minimumSupportedOperatingSystem": {
                                            "v4_0":  true
                                        },
    "@odata.type":  "#microsoft.graph.androidLOBApp",
    "identityVersion":  "10",
    "privacyInformationUrl":  null,
    "notes":  "",
    "informationUrl":  null,
    "developer":  "",
    "publisher":  "A Online Radio",
    "identityName":  "com.leadapps.android.radio.ncp",
    "isFeatured":  false,
    "VersionName": "1.0.5.4"
}
```

<b>2.</b> Create Content Version for the new LOB application
This is completed by constructing a URI consisting of the application ID and LOB Application Type. There are the following application types used:
+	microsoft.graph.androidLOBApp
+	microsoft.graph.iosLOBApp
+	microsoft.graph.windowsMobileMSI

Properties:
“ApplicationId” is the ID of the created LOB application in section “1. Create LOB Application in the Intune Service”

```
POST - deviceAppManagement/mobileApps/ApplicationId/LOBType/contentVersions
```

Example of a constructed Android URI to create the content Versions:

```
POST - https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/b0d93c43-1eba-4585-b883-fe1fe0370113/microsoft.graph.androidLOBApp/contentVersions
```

<b>3.</b>	Encrypt file and Get File Information
The next step is to encrypt the file locally and get the file size and encrypted size.
  +	A temporary file name is created with extension "filename_temp.bin" from the actually file (IPA, APK, MSI)
	+ The function EncyptFile is used to pass the SourceFile and TempFile variables to start the encryption process
  +	The encryption uses “System.Security.Cryptography.Aes.CreateEncryptor” method to create a cryptographic stream for securing your app. For more details, see the script function EncryptFileWithIV.
  +	After encryption, a manifest file is built for installing your new app on the target device.

<b>4.</b>	Create a new Application Content File for the application
Once you have the encrypted file and the metadata, the Intune service requires an Application Content File entry to be created with these details populated:
+	SizeEncrypted – The size of the “Filename_Temp.bin” encypted file
+	Size – The size of the original file
+	Manifest – This information that Intune uses to install the application on the device
+	Name – The name of the file being uploaded
+	@odata.type – The defined type for the application file content

#### Sample Android File Content

```JSON
{

    "sizeEncrypted":  363104,
    "manifest":  "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48QW5kcm9pZE1hbmlmZXN0UHJvcGVydGllcyB4bWxuczp4c2Q9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIj48UGFja2FnZT5jb20ubGVhZGFwcHMuYW5kcm9pZC5yYWRpby5uY3A8L1BhY2thZ2U+PFBhY2thZ2VWZXJzaW9uQ29kZT4xMDwvUGFja2FnZVZlcnNpb25Db2RlPjxQYWNrYWdlVmVyc2lvbk5hbWU+MTA8L1BhY2thZ2VWZXJzaW9uTmFtZT48QXBwbGljYXRpb25OYW1lPkFfT25saW5lX1JhZGlvXzEuMC41LjQuYXBrPC9BcHBsaWNhdGlvbk5hbWU+PE1pblNka1ZlcnNpb24+MzwvTWluU2RrVmVyc2lvbj48QVdUVmVyc2lvbj48L0FXVFZlcnNpb24+PC9BbmRyb2lkTWFuaWZlc3RQcm9wZXJ0aWVzPg==",
    "name":  "A_Online_Radio_1.0.5.4.apk",
    "size":  363051,
    "@odata.type":  "#microsoft.graph.mobileAppContentFile"
}
```


Properties:
“ApplicationId” is the ID of the created LOB application in section 1. Create LOB Application in the Intune Service.
"contentVersionId" is the ID of the content version creates in section 2. Create Content Version for the new LOB application

```
POST - deviceAppManagement/mobileApps/ApplicationId/LOBType/contentVersions/ contentVersionId/files
```

Example of a constructed Android URI to create the Application Content File:

```
POST - https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/b0d93c43-1eba-4585-b883-fe1fe0370113/microsoft.graph.androidLOBApp/contentVersions/1/files
```

<b>5.</b>	Wait for File Processing – Application Content File

Once the POST request for the Application Content File has completed, the Intune Service needs to wait for the POST request to be processed so that certain properties are populated and available. The key property that the service requires is the “AzureStorageURI”, which is the location to upload the encrypted file to.

To complete this action, you call a GET request against the following resource path until the “AzureStorageURI” is populated and ready for upload.

Properties:
“ApplicationId” is the ID of the created LOB application in section “1. Create LOB Application in the Intune Service”.
“contentVersionId” is the ID of the content version creates in section “2.	 Create Content Version for the new LOB application”
“fileId” is the ID of the application content file created in section “4. Create a new Application Content File for the application”

```
GET - deviceAppManagement/mobileApps/ApplicationId/LOBType/contentVersions/ contentVersionId/files/fileId
```

Example of a constructed Android URI to get the application content file request status:

```
GET - https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/b0d93c43-1eba-4585-b883-fe1fe0370113/microsoft.graph.androidLOBApp/contentVersions/1/files/a9703f15-a67d-4d16-9774-5b8c18b9ca92
```

<b>6.</b>	Upload the content to Azure Storage
Once the “AzureStorageURI” is ready the “UploadFileToAzureStorage” is called with two parameters $SasUri and $filepath.
##### Parameters:

+ $SasUri – This is the azure storage URI created by the Intune Service
+ $filePath – This is the path to the encrypted file
The file is split into chunks (default: 1Mb) to upload to the Intune Service SAS URI location. Once all the chunks are uploaded to the service using the function “UploadAzureStorageChunk” a final function needs to be used to finalize the upload. The finalization takes all the chunk ids and joins them back together to recreate the file, this is done using the “FinalizeAzureStorageUpload” function.


<b>7.</b>	Commit the file

Once the file is uploaded and finalized, you need to commit the file into storage by passing a JSON object with the file encryption information.

```
{

    "fileEncryptionInfo": {
                               "fileDigestAlgorithm":  "SHA256",
                               "encryptionKey":  " XqV0jLbcp+9QhpYReX1JmgTunzR0LrTfV4U/HUQdkgM =",
                               "initializationVector":  "tThBLZsLX3k0NV7qld3D/A==",
                               "fileDigest":  " jkI06TE3y+MRlz2Mzatm46jc3xeDw+8Bxn+dievp+Tc =",
                               "mac":  "kMTKEHMbkxh4MuTrw7OtB26bSH2xynZJ5d6GCox5DZ0=",
                               "profileIdentifier":  "ProfileVersion1",
                               "macKey":  " XqV0jLbcp+9QhpYReX1JmgTunzR0LrTfV4U/HUQdkgM ="
                           }
}
```

Properties:
+ “ApplicationId” is the ID of the created LOB application in section “1. Create LOB Application in the Intune Service”.
+ “contentVersionId” is the ID of the content version creates in section “2.	 Create Content Version for the new LOB application”
+ “fileId” is the ID of the application content file created in section “4. Create a new Application Content File for the application”

To commit the file the following URI is used:

```
POST - deviceAppManagement/mobileApps/ApplicationId/LOBType/contentVersions/ contentVersionId/files/fileId/commit
```

Example of a constructed Android URI to commit the file:

```
POST - https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/5e8d38b1-b5a6-4558-9c9b-6cd2d0705850/microsoft.graph.androidLOBApp/contentVersions/1/files/29846422-46d1-4869-b293-b819588b8cd5/commit
```
<b>8.</b>	Wait for File Processing – File Commit
Once the POST request for the file commit has completed, the Intune Service needs to wait for the POST request to be processed.
To complete this action, you call a GET request against the following resource path until the “CommitFile” is successful.

Properties:
“ApplicationId” is the ID of the created LOB application in section “1. Create LOB Application in the Intune Service”.

```
GET - deviceAppManagement/mobileApps/ApplicationId
```

Example of a constructed Android URI to get the application content file request status:

```
GET - https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/b0d93c43-1eba-4585-b883-fe1fe0370113
```
<b>9.</b>	Commit the app
The final stage is committing the application into the service by passing JSON data with the “committedContentVersion”. Once the version is committed its available to assign to a group.

```JSON
{
    "@odata.type":  "#microsoft.graph.androidLOBApp",
    "committedContentVersion":  "1"
}
```


#### Properties:
+ “ApplicationId” is the ID of the created LOB application in section “1. Create LOB Application in the Intune Service”.

```
PATCH - deviceAppManagement/mobileApps/ApplicationId
```

Example of a constructed Android URI to commit the application:

```
PATCH - https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/5e8d38b1-b5a6-4558-9c9b-6cd2d0705850
```

### Running the script
To use the script after installing the pre-requisites, you can modify the sample installation command at the end of the script to match the type of LOB application you want to upload:
Android

#### Without Android SDK - All parameters are specified
```
Upload-AndroidLob -sourceFile "C:\Software\OnlineRadio\A_Online_Radio_1.0.5.4.apk" -publisher "A Online Radio" -description "A Online Radio 1.0.5.4" -identityName "com.leadapps.android.radio.ncp" -identityVersion "10" -versionName "1.0.5.4"
```

#### With Android SDK:
```
Upload-AndroidLob -sourceFile "C:\Software\OnlineRadio\A_Online_Radio_1.0.5.4.apk" -publisher "A Online Radio" -description "A Online Radio 1.0.5.4"
```

If used, the Android SDK lookup will find the “identityName” and “identityVersion”.

#### MSI
```
Upload-MSILob "C:\Software\Orca\Orca.Msi" -publisher "Microsoft" -description "Orca"
```

#### iOS
```
Upload-iOSLob -sourceFile "C:\Software\iOS\MyApp.ipa" -displayName "MyApp.ipa" -publisher "MyApp" -description "MyApp" -bundleId "com.microsoft.myApp" -identityVersion "1.0.0.0" -versionNumber "3.0.0" -expirationDateTime "2018-04-14T20:53:52Z"
```

## 2. Win32_Application_Add.ps1
The following script sample provides the ability to upload a Win32 application to the Intune Service. For more information on creating an Intunewin file review the below article:

https://docs.microsoft.com/en-us/intune/apps-win32-app-management

### Prerequisites
To use Win32 app management, be sure you meet the following criteria:

+ Windows 10 version 1607 or later (Enterprise, Pro, and Education versions)

### Script parameters
The following parameters are required when uploading an Intunewin file via this script sample:

+ SourceFile - This is the path to the Intunewin file
+ Publisher - The publisher of the application
+ Description - Description of the application
+ DetectionRules - The detection rules for the application
+ ReturnCodes - The returncodes for the application

An example of this can be found below:

```PowerShell
# Win32 Application Upload
Upload-Win32Lob -SourceFile "$SourceFile" -publisher "Publisher" -description "Description" -detectionRules $DetectionRule -returnCodes $ReturnCodes
```
There are other parameters that can be specified, these include:

+ displayName - This can be used to specify the application Name
+ installCmdLine - The complete installation command line for application installation
+ uninstallCmdLine - The complete installation command line for application uninstall
+ installExperience - You can configure a Win32 app to be installed in User or System context. User context refers to only a given user. System context refers to all users of a Windows 10 device.

An example of this is below:

```PowerShell
# Win32 Application Upload
Upload-Win32Lob -SourceFile "$SourceFile" -displayName "Application Name" -publisher "Publisher" -description "Description" -detectionRules $DetectionRule -returnCodes $ReturnCodes
-installCmdLine "powershell.exe -executionpolicy Bypass .\install.ps1" -uninstallCmdLine "powershell.exe -executionpolicy Bypass .\uninstall.ps1"
```

### Detection Rules
The following section will provide samples on how to create detection rules and how to add multiple rules.

#### File Rule
To create a file detection rule the following can be used:

```PowerShell
# Defining Intunewin32 detectionRules
$FileRule = New-DetectionRule -File -Path "C:\Program Files\ProgramName" -FileOrFolderName "program.exe" -FileDetectionType exists -check32BitOn64System False
```

#### MSI Rule
To create an MSI detection rule the following can be used:

```PowerShell
$MSIRule = New-DetectionRule -MSI -MSIproductCode "{23170F69-40B1-2702-1604-000001000000}"
```

If the intunewin file your creating is an MSI you can use the MSI codes stored in the detection.xml file inside the package. This is completed by using the Get-IntuneWinXML function to open the SourceFile and then extracting the detection.xml.

```PowerShell
# Defining Intunewin32 detectionRules
$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

$MSIRule = New-DetectionRule -MSI -MSIproductCode $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode
```

#### Registry Rule
To create a Registry detection rule the following can be used:

```PowerShell
# Defining Intunewin32 detectionRules
$RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\App" -RegistryDetectionType exists -check32BitRegOn64System True
```

#### PowerShell Script rule
To create an app specific script rule that is used to detect the presence of the app, the following example can be used:

```PowerShell
$PowerShellScript = "C:\Scripts\script.ps1"

$PowerShellRule = New-DetectionRule -PowerShell -ScriptFile "$PowerShellScript" `
-enforceSignatureCheck $false -runAs32Bit $true

# Creating Array for detection Rule
$DetectionRule = @($PowerShellRule)
```

#### Detection Rule Construction
To create and add multiple detection rules (i.e. File, Registry, MSI) the sample script requires each variable to be passed into an array, once its in an array it can be passed to the JSON object. Example below:

```PowerShell
# Defining Intunewin32 detectionRules
$FileRule = New-DetectionRule -File -Path "C:\Program Files\Program" -FileOrFolderName "program.exe" -FileDetectionType exists -check32BitOn64System False

$RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\App" -RegistryDetectionType exists -check32BitRegOn64System True

$MSIRule = New-DetectionRule -MSI -MSIproductCode "{23170F69-40B1-2702-1604-000001000000}"

# Creating Array for detection Rule
$DetectionRule = @($FileRule,$RegistryRule,$MSIRule)
```
### Return Codes
Return codes are used to indicate post-installation behavior. When you add an application via the Intune UI there are five default rules created:

+ ReturnCode = 0 -> Success
+ ReturnCode = 1707 -> Success
+ ReturnCode = 3010 -> Soft Reboot
+ ReturnCode = 1641 -> Hard Reboot
+ ReturnCode = 1618 -> Retry

The sample script requires return codes to be specified. If the default return codes are valid then you can use the following to get all the default return codes:

```PowerShell
$ReturnCodes = Get-DefaultReturnCodes
```

If you want to use the Default return codes but want to add some extra return codes then you can use the following:

```PowerShell
$ReturnCodes = Get-DefaultReturnCodes

$ReturnCodes += New-ReturnCode -returnCode 142 -type softReboot
$ReturnCodes += New-ReturnCode -returnCode 339 -type softReboot
```

If you don't want to include the default return codes, then you need to create an array on the return codes, sample below:

```PowerShell
$ReturnCode1 = New-ReturnCode -returnCode 142 -type softReboot
$ReturnCode2 = New-ReturnCode -returnCode 339 -type softReboot

# Creating Array for ReturnCodes
#$ReturnCodes = @($ReturnCode1,$ReturnCode2)
```
Once you have constructed your return codes then they can be passed to the Upload-Win32Lob function.

### Running the script
To run the sample script you can modify the samples below to match the type and conditions you want to upload:

#### Sample 1
PowerShell Detection Rule and default return codes

```PowerShell
$SourceFile = "C:\packages\package.intunewin"

$PowerShellScript = "C:\Scripts\sample.ps1"

$PowerShellRule = New-DetectionRule -PowerShell -ScriptFile "$PowerShellScript" -enforceSignatureCheck $false -runAs32Bit $true

# Creating Array for detection Rule
$DetectionRule = @($PowerShellRule)

$ReturnCodes = Get-DefaultReturnCodes

# Win32 Application Upload
Upload-Win32Lob -SourceFile "$SourceFile" -publisher "Publisher" -description "Description" -detectionRules $DetectionRule -returnCodes $ReturnCodes -installCmdLine "powershell.exe -executionpolicy Bypass .\install.ps1" -uninstallCmdLine "powershell.exe -executionpolicy Bypass .\uninstall.ps1"
```

#### Sample 2
Multiple Detection Rules including file, registry and MSI, plus default return codes with some additional return codes.

```PowerShell
$SourceFile = "C:\packages\package.intunewin"

# Defining Intunewin32 detectionRules
$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

# Defining Intunewin32 detectionRules
$FileRule = New-DetectionRule -File -Path "C:\Program Files\Application" -FileOrFolderName "application.exe" -FileDetectionType exists -check32BitOn64System False

$RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\Program" -RegistryDetectionType exists -check32BitRegOn64System True

$MSIRule = New-DetectionRule -MSI -MSIproductCode $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode

# Creating Array for detection Rule
$DetectionRule = @($FileRule,$RegistryRule,$MSIRule)

$ReturnCodes = Get-DefaultReturnCodes

$ReturnCodes += New-ReturnCode -returnCode 302 -type softReboot
$ReturnCodes += New-ReturnCode -returnCode 145 -type hardReboot

# Win32 Application Upload
Upload-Win32Lob -SourceFile "$SourceFile" -publisher "Publisher" -description "Description" -detectionRules $DetectionRule -returnCodes $ReturnCodes
```

#### Sample 3
Single File Detection Rule, plus specific return codes.

```PowerShell
$SourceFile = "C:\packages\package.intunewin"

# Defining Intunewin32 detectionRules
$FileRule = New-DetectionRule -File -Path "C:\Program Files\Application" -FileOrFolderName "application.exe" -FileDetectionType exists -check32BitOn64System False

# Creating Array for detection Rule
$DetectionRule = @($FileRule)

$ReturnCode1 = New-ReturnCode -returnCode 0 -type success
$ReturnCode2 = New-ReturnCode -returnCode 1618 -type retry
$ReturnCode3 = New-ReturnCode -returnCode 302 -type softReboot
$ReturnCode4 = New-ReturnCode -returnCode 145 -type hardReboot

# Creating Array for ReturnCodes
$ReturnCodes = @($ReturnCode1,$ReturnCode2,$ReturnCode3,$ReturnCode4)

# Win32 Application Upload
Upload-Win32Lob -SourceFile "$SourceFile" -publisher "Publisher" -description "Description" -detectionRules $DetectionRule -returnCodes $ReturnCodes
```
