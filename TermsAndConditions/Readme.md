# Intune Terms and Conditions script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. TermsAndConditions_Add.ps1
This script adds a terms and conditions policy into the Intune Service that you have authenticated with. The policy created by the script is shown below in the Sample JSON section below.

#### Add-TermsAndConditions Function
This function is used to add a terms and conditions policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-TermsAndConditions -JSON $JSON
```

#### Test-JSON Function
This function is used to test if the JSON passed to the Add-TermsAndConditions function is valid, if the JSON isn't valid then it will return a failure otherwise it will run a POST request to the Graph Service.

The sample JSON files are shown below:

#### Sample JSON

```JSON
{
    "@odata.type": "#microsoft.graph.termsAndConditions",
    "displayName":"Customer Terms and Conditions",
    "title":"Terms and Conditions",
    "description":"Desription of the terms and conditions",
    "bodyText":"This is where the body text for the terms and conditions is set\n\nTest Web Address - https://www.bing.com\n\nCustomer IT Department",
    "acceptanceStatement":"Acceptance statement text goes here",
    "version":1
}
```
### 2. TermsAndConditions_Add_Assign.ps1
This script adds a terms and conditions policy into the Intune Service that you have authenticated with. The policy created by the script is shown below in the Sample JSON section below.

#### Add-TermsAndConditions Function
This function is used to add a terms and conditions policy to the Intune Service. It supports a single parameter -JSON as an input to the function to pass the JSON data to the service.

```
Add-TermsAndConditions -JSON $JSON
```
#### Assign-TermsAndConditions Function
This function is used to assign terms and conditions to an AAD Group. There are two required parameters.

+ id - The ID of the terms and conditions in the Intune Service
+ TargetGroupId - The ID of the AAD Group you want to assign the policy to

```PowerShell
Assign-TermsAndConditions -id $id -TargetGroupId $TargetGroupId
```
#### Get-AADGroup Function
This function is used to get an AAD Group by -GroupName to be used to assign an application to.

```PowerShell
$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where terms and conditions will be assigned"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }
```

### 3. TermsAndConditions_Get.ps1
This script gets all terms and conditions policies from the Intune Service that you have authenticated with.

#### Get-TermsAndConditions Function
This function is used to get all terms and conditions policies from the Intune Service.

It supports a single parameters as an input to the function to pull data from the service.

```PowerShell
# Returns all terms and conditions policies configured in Intune
Get-TermsAndConditions

# Returns a terms and conditions policy that contains the Name configured in Intune
Get-TermsAndConditions -Name "Test Policy"
```

### 4. TermsAndConditions_Remove.ps1
This script removes a terms and conditions policy configured in the Intune Service that you have authenticated with.

####  Remove-TermsAndCondition Function
This function is used to remove a terms and conditions policy from the Intune Service.

It supports a single parameter -id as an input to the function to specify the id of the terms and conditions policy that you wish to remove. The script will get a policy of choice via the -Name parameter and then remove it if it's valid.

```PowerShell
# Removes an individual terms and conditions policy from the Intune Service
$TC = Get-TermsAndConditions -Name "Customer"

Remove-TermsAndCondition -termsAndConditionId $TC.id

```
