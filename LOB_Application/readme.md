# Intune Line of Business App Upload – PowerShell Script readme and guide

Documentation for Intune and Microsoft Graph can be found here Intune Graph Documentation: https://developer.microsoft.com/en-us/graph/docs/concepts/overview.

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account.
## Introduction
The Microsoft Graph API for Intune provides the same facilities as does the Intune user interface so, automating manual tasks is a relatively straightforward programming process. In the case of a line of business (LOB) application, there are several additional steps required to complete the upload of the application file. This readme provides an overview and step-by-step guidance for uploading your line of business applications to Intune.
## Prerequisites
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
