# Certificate Authority script samples

This repository of PowerShell sample scripts show how to access Intune service resources.  They demonstrate this by making HTTPS RESTful API requests to the Microsoft Graph API from PowerShell.

Documentation for Intune and Microsoft Graph can be found here [Intune Graph Documentation](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

#### Disclaimer
Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account. 

Within this section there are the following scripts with the explanation of usage.

### 1. CertificateConnector_Get.ps1
This script shows all Certificate Connectors configured in the Intune Service that you have authenticated with.

#### Get-CertificateConnector Function
This function is used to get all Certificate Connectors configured in the Intune Service.

```PowerShell
# Returns all Certificate Connectors configured in Intune
Get-CertificateConnector

# Returns a specific Certificate Connector by name configured in Intune
Get-CertificateConnector -Name "certificate_connector_3/20/2017_10:52 AM"
```

### 2. Validate-NDESConfig.ps1
Validate-NDESConfig.ps1 highlights configuration issues on an NDES server, as configured for use with Intune Standalone SCEP certificates.

The script checks the configuration of your NDES server and ensures it aligns to the "Configure and manage SCEP certificates with Intune" article.

This script is used purely to validate the configuration. All remedial tasks will need to be carried out manually. Where possible, a link and section description is provided.

https://docs.microsoft.com/en-us/intune/certificates-scep-configure#configure-your-infrastructure

#### Prerequisites
Use of this script requires the following:
* Script should be ran directly on the NDES Server
* An account with permissions to administer NDES
* Requires PowerShell version 3.0 at a minimum
* Requires PowerShell to be Run As Administrator

#### Usage
To run the script, the following examples are below:
```
.EXAMPLE
.\Validate-NDESConfig.ps1 -NDESServiceAccount Contoso\NDES_SVC -IssuingCAServerFQDN IssuingCA.contoso.com -SCEPUserCertTemplate SCEPGeneral

.\Validate-NDESConfig.ps1 -help
```
