# Intune Apple Enrollment script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. BulkAssignProfile.ps1
This script reads the first 1000 Apple Dep devices which are not assigned to any profile and assigns the given enrollment profile id to it. If there are more than 1000 devices to assign, simply run the script more than once.

WARNING: Before running the script, get the correct enrollment profile id from Ibiza UI (check the profile url during profile edit) and assign it to the profileId variable as shown below. By default, profile id is empty to keep the script safe. 

```PowerShell

$global:profileId = ''
# $global:profileId = '<<profileguid>>'

```

It supports two parameters as an input to the function to pull data from the service.

```PowerShell
# Prompt for the Intune user name and password to use to read, assign the first 1000 Apple Dep devices.
BulkAssignProfile.ps1

# Read, assign the first 1000 Apple Dep devices.
BulkAssignProfile.ps1 -User "admin@asdf.onmicrosoft.com" -Password "Secret!"

```
