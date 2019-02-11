# Graph Batch script sample

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

#### Graph Batch
JSON batching allows you to optimize your application by combining multiple requests into a single JSON object. For example, a client might want to compose a view of unrelated data such as:

1. An image stored in OneDrive
2. A list of Planner tasks
3. The calendar for a group

Combining these three individual requests into a single batch request can save the application **significant network latency.**

#### Request format

Batch requests are always sent using **POST** to the **$batch** endpoint.

A JSON batch request body consists of a single JSON object with one required property: requests. The requests property is an array of individual requests. For each individual request, the id, method, and url properties are required.

The id property functions primarily as a correlation value to associate individual responses with requests. This allows the server to process requests in the batch in the most efficient order.

The method and url properties are exactly what you would see at the start of any given HTTP request. The method is the HTTP method, and the URL is the resource URL the individual request would typically be sent to.

Individual requests can optionally also contain a headers property and a body property. Both of these properties are typically JSON objects, as shown in the previous example. In some cases, the body might be a base64 URL-encoded value rather than a JSON object - for example, when the body is an image. When a body is included with the request, the headers object must contain a value for Content-Type.

https://docs.microsoft.com/en-us/graph/json-batching

### 1. Batch_Post.ps1
This script requests Graph queries to the Intune Service that you have authenticated with.

The Batch requests runs a GET against the following elements:

* Intune Compliance Policies
* Intune Configuration Policies
* Intune Client Applications


```JSON
{
  "requests": [
    {
      "id": "1",
      "method": "GET",
      "url": "/deviceManagement/deviceCompliancePolicies"
    },
    {
      "id": "2",
      "method": "GET",
      "url": "/deviceManagement/deviceConfigurations"
    },
    {
      "id": "3",
      "method": "GET",
      "url": "/deviceAppManagement/mobileApps"
    }
  ]
}
```
Once the batch requests are returned they can be viewed from the responses.

```PowerShell
$uri = "https://graph.microsoft.com/beta/`$batch"

$Post = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $batch -ContentType "application/json"

foreach($Element in $Post.responses.body){

    Write-Host $Element.'@odata.context' -ForegroundColor Cyan
    Write-Host "Reponse Count:"$Element.value.count -ForegroundColor Yellow
    $Element.value.displayName
    Write-Host

}
```
