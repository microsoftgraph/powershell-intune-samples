# Intune Corporate Device Enrollment script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. CorpDeviceEnrollment_Add.ps1
This script adds a Corporate Device Enrollment identifier to the Intune Service that you have authenticated with.

#### Add-CorporateDeviceIdentifiers Function
This function is used to add a Corporate Device Enrollment Identifier to the Intune Service.

```PowerShell
# Adds a IMEI Corporate Device Enrollment Identifiers to Intune
Add-CorporateDeviceIdentifiers -IdentifierType imei -OverwriteImportedDeviceIdentities false -Identifier "123456789012345" -Description "IMEI Device"

# Adds a SerialNumber Corporate Device Enrollment Identifiers to Intune
Add-CorporateDeviceIdentifiers -IdentifierType SerialNumber -OverwriteImportedDeviceIdentities false -Identifier "12345678901234" -Description "SerialNumber Device"
```

### 2. CorpDeviceEnrollment_Export.ps1
This script gets all the Corporate Device Enrollment Identifiers from the Intune Service that you have authenticated with. The script will then export the Device Identifiers to .csv format in the directory of your choice.

```PowerShell
$ExportPath = Read-Host -Prompt "Please specify a path to export the Corporate Device Identifiers to e.g. C:\IntuneOutput"

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
Example CSV export:
```CSV
355450075770212,device1
355450075770213,device2
```

#### Get-CorporateDeviceIdentifiers Function
This function is used to get all Corporate Device Enrollment Identifiers from the Intune Service.

```PowerShell
# Returns all Corporate Device Enrollment Identifiers configured in Intune
Get-CorporateDeviceIdentifiers

# Returns a specific Corporate Device Identifier configured in Intune
Get-CorporateDeviceIdentifiers -DeviceIdentifier "123456789012345"
```

### 3. CorpDeviceEnrollment_Get.ps1
This script gets all the Corporate Device Enrollment identifiers from the Intune Service that you have authenticated with.

#### Get-CorporateDeviceIdentifiers Function
This function is used to get all Corporate Device Enrollment Identifiers from the Intune Service.

```PowerShell
# Returns all Corporate Device Enrollment Identifiers configured in Intune
Get-CorporateDeviceIdentifiers

# Returns a specific Corporate Device Identifier configured in Intune
Get-CorporateDeviceIdentifiers -DeviceIdentifier "123456789012345"

```
### 4. CorpDeviceEnrollment_Remove.ps1
This script removes a Corporate Device identifier from the Intune Service that you have authenticated with.

#### Get-CorporateDeviceIdentifiers Function
This function is used to get all Corporate Device Enrollment Identifiers from the Intune Service.

```PowerShell
# Returns all Corporate Device Enrollment Identifiers configured in Intune
Get-CorporateDeviceIdentifiers

# Returns a specific Corporate Device Identifier configured in Intune
Get-CorporateDeviceIdentifiers -DeviceIdentifier "123456789012345"

```

#### Remove-CorporateDeviceIdentifier Function
This function is used to remove a Corporate Device Identifier from the Intune Service.

```PowerShell
# Returns all Corporate Device Enrollment Identifiers configured in Intune
Remove-CorporateDeviceIdentifier -ImportedDeviceId "123456789012345"

```
