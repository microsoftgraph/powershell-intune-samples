# Graph Paging script sample

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

#### Graph Paging
When Microsoft Graph requests return too much information (More than a 1000 results) to show on one page, you can use paging to break the information into manageable chunks.

You can page forward and backward in Microsoft Graph responses. A response that contains paged results will include a skip token (odata.nextLink) that allows you to get the next page of results.

https://developer.microsoft.com/en-us/graph/docs/concepts/paging

### 1. ManagedDevices_Get_Paging.ps1
This script returns all managed devices added to the Intune Service that you have authenticated with.

There are the following functions used:

#### Get-ManagedDevices - Function
This function is used to get all managed devices from the Intune Service.
```PowerShell
Get-ManagedDevices
```

Within the function is the paging call which looks for "@odata.nextLink" from the returned response. If the response returns "@odata.nextLink" then a while loop is called to request the next set of results.

```
$DevicesResponse = (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get -Verbose)

    $Devices = $DevicesResponse.value

    $DevicesNextLink = $DevicesResponse."@odata.nextLink"

        while ($DevicesNextLink -ne $null){

            $DevicesResponse = (Invoke-RestMethod -Uri $DevicesNextLink –Headers $authToken –Method Get -Verbose)
            $DevicesNextLink = $DevicesResponse."@odata.nextLink"
            $Devices += $DevicesResponse.value

        }
```
