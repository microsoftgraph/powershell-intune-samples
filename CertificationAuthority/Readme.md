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

### 2. Validate-NDESConfiguration.ps1
Validate-NDESConfiguration.ps1 highlights configuration issues on an NDES server, as configured for use with Intune Standalone SCEP certificates.

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
.\Validate-NDESConfiguration.ps1 -NDESServiceAccount Contoso\NDES_SVC -IssuingCAServerFQDN IssuingCA.contoso.com -SCEPUserCertTemplate SCEPGeneral

.\Validate-NDESConfiguration.ps1 -help
```
### 3. Validate-NDESUrl.ps1
Validate-NDESUrl.ps1 will ensure requests from devices enrolled in Microsoft Intune and targeted with a SCEP policy will successfully traverse the network path to the NDES server. Since the certificate request includes a query string that is longer than what is allowed by the default settings in Windows IIS and some reverse proxy servers, those servers and network devices must be configured to allow long query strings and web requests.

https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/requestlimits/

This tool will simulate a SCEP request with a large payload, enabling you to check the IIS logs on the NDES server to ensure that the request is not being blocked anywhere along the path.

A query size of 30 is suggested as a starting point – success with this size suggests a valid configuration through the network path.

#### Prerequisites
Use of this script requires the following:
* This script should be run from a client machine with Internet access, not on the NDES server
* Requires PowerShell version 4.0 at a minimum
* Requires PowerShell to be Run As Administrator

#### Usage
To run the script, the following examples are below:
```PowerShell
.EXAMPLE
.\Validate-NDESUrl.ps1 -server externalDNSName.contoso.com -q 30

.\Validate-NDESUrl.ps1 -help
```

##### Known Issue
When the Validate-NDESUrl.ps1 script is used, an event is logged in the Microsoft-Windows-NetworkDeviceEnrollmentService crimson channel. This is caused by the spoofed SCEP request which is used to determine whether the large payload can traverse the network path. If you are going to use the Validate-NDESConfiguration.ps1 script to validate your NDES server configuration, you should ideally run that before using this script. This will prevent the events being picked up in the server validation output.

Example event:
```
Source        : Microsoft-Windows-NetworkDeviceEnrollmentService
Message       : The Network Device Enrollment Service cannot retrieve required information, such as the transaction ID, message type, or signing certificate, from the client's PKCS7 message (0x8009310b).  ASN1 bad tag value met.
```
