---
page_type: sample
products:
- ms-graph
languages:
- powershell
extensions:
  contentType: samples
  technologies:
  - Microsoft Graph 
  services:
  - Intune
  createdDate: 4/4/2017 9:41:27 AM
---
# Ejemplos de Graph de Intune

Este repositorio de scripts de ejemplo de PowerShell muestra cómo obtener acceso a los recursos del servicio Intune. Lo muestran haciendo solicitudes de la API de REST de HTTPS a la API de Microsoft Graph desde PowerShell.

La documentación de Intune y Microsoft Graph se encuentra aquí [Documentación de Graph de Intune](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

En estos ejemplos se muestran las acciones de administrador de Intune o de asociado de Microsoft habituales para administrar recursos de Intune.

Los siguientes ejemplos se incluyen en este repositorio:
- AdminConsent
- AndroidEnterprise
- AppleEnrollment
- Applications
- ApplicationSync
- AppProtectionPolicy
- Auditing
- Authentication
- CertificationAuthority
- CheckStatus
- CompanyPortalBranding
- CompliancePolicy
- CorporateDeviceEnrollment
- DeviceConfiguration
- EnrollmentRestrictions
- IntuneDataExport
- LOB_Application
- ManagedDevices
- Paging
- RBAC
- RemoteActionAudit
- SoftwareUpdates
- TermsAndConditions
- UserPolicyReport

Los scripts se otorgan bajo licencia "tal cual" en la licencia MIT.

#### Aviso de declinación de responsabilidades
Algunos ejemplos de script recuperan información de su espacio empresarial de Intune y otras crean, eliminan o actualizan los datos en el espacio empresarial de Intune.  Debe comprender el impacto de cada script de ejemplo antes de ejecutarlo, los ejemplos se deben ejecutar con una cuenta de inquilino que no es de producción o "de prueba". 

## Usar la API de Graph de Intune
La API de Graph de Intune permite el acceso mediante programación a la información de Intune para su espacio empresarial y la API realiza las mismas operaciones de Intune que las que están disponibles a través de Azure Portal.  

Intune proporciona datos a Microsoft Graph igual que lo hacen otros servicios en la nube, con navegación de relaciones e información sobre entidades enriquecida.  Use Microsoft Graph para combinar la información de otros servicios e Intune y crear aplicaciones de servicios cruzados completas para profesionales de TI o usuarios finales.     

## Requisitos previos
El uso de estos ejemplos de PowerShell de Intune de la API de Microsoft Graph requiere lo siguiente:
* Instalar el módulo de AzureAD PowerShell ejecutando "Install-Module AzureAD" o "Install-Module AzureADPreview" desde un símbolo del sistema de PowerShell con privilegios elevados
* Un espacio empresarial de Intune que admita Azure Portal con una licencia de producción o de prueba (https://docs.microsoft.com/en-us/intune-azure/introduction/what-is-microsoft-intune)
* Usar las API de Microsoft Graph para configurar las directivas y los controles de Intune requiere una licencia de Intune.
* Una cuenta con permisos para administrar el servicio de Intune
* PowerShell v5.0 en Windows 10 x64 (PowerShell v4.0 es un requisito mínimo para que los scripts funcionen correctamente)
* Nota: En el caso de PowerShell 4.0 necesitará el módulo [PowershellGet Module for PS 4.0](https://www.microsoft.com/en-us/download/details.aspx?id=51451) para habilitar el uso de la función Install-Module
* El uso de estos scripts por primera vez requiere que un administrador global del espacio empresarial acepte los permisos de la aplicación

## Introducción
Después de que se instalen o se cumplan los requisitos previos, lleve a cabo los siguientes pasos para usar estos scripts:

#### 1. Uso del script

1. Descargue el contenido del repositorio en su equipo local de Windows
* Extraiga los archivos en una carpeta local (por ejemplo, C:\IntuneGraphSamples)
* En el menú Inicio ejecute PowerShell x64
* Desplácese hasta el directorio (p. ej., cd C:\IntuneGraphSamples)
* Por cada carpeta en el repositorio local, puede ir a ese directorio y ejecutar el script que prefiera.
* Uso de script de aplicación de ejemplo:
  * Para usar los scripts de Administrar aplicaciones, en C:\IntuneGraphSamples, ejecute "cd .\Applications\".
  * Una vez en la carpeta ejecute .\Application_MDM_Get.ps1
  para obtener todas las aplicaciones agregadas por MDM Esta secuencia de pasos se puede usar para cada carpeta....

#### 2. Autenticación con Microsoft Graph
La primera vez que ejecute estos scripts, se le pedirá que proporcione una cuenta para autenticar con el servicio:
```
Please specify your user principal name for Azure Authentication:
```
Una vez que haya proporcionado un nombre principal de usuario, se abrirá una ventana emergente en la que se le solicitará la contraseña. Cuando la autenticación de Azure Active Directory se realice correctamente, el token de usuario durará una hora, cuando pase la hora en la sesión de PowerShell, se le solicitará que vuelva a autenticarse.

Si está ejecutando el script por primera vez en su espacio empresarial, se mostrará un mensaje emergente en el que se indicará lo siguiente:

```
Microsoft Intune PowerShell needs permission to:

* Sign you in and read your profile
* Read all groups
* Read directory data
* Read and write Microsoft Intune Device Configuration and Policies (preview)
* Read and write Microsoft Intune RBAC settings (preview)
* Perform user-impacting remote actions on Microsoft Intune devices (preview)
* Sign in as you
* Read and write Microsoft Intune devices (preview)
* Read and write all groups
* Read and write Microsoft Intune configuration (preview)
* Read and write Microsoft Intune apps (preview)
```

Nota: Si su cuenta de usuario tiene como objetivo el acceso condicional basado en el dispositivo, el dispositivo debe estar inscrito o ser compatible para poder realizar la autenticación de forma correcta.

## Colaboradores

Si quiere hacer su aportación a este ejemplo, vea CONTRIBUTING.MD.

Este proyecto ha adoptado el Código de conducta de código abierto de Microsoft. Para obtener más información, vea Preguntas frecuentes sobre el código de conducta o póngase en contacto con opencode@microsoft.com si tiene otras preguntas o comentarios.

## Preguntas y comentarios

Nos encantaría recibir sus comentarios sobre el ejemplo de PowerShell de Intune. Puede enviarnos sus preguntas y sugerencias a través de la sección Problemas de este repositorio.

Su opinión es importante para nosotros. Conéctese con nosotros en Stack Overflow. Etiquete sus preguntas con \[MicrosoftGraph] y \[intune].


## Recursos adicionales
* [Documentación de la API de Microsoft Graph](https://developer.microsoft.com/en-us/graph/docs)
* [Portal de Microsoft Graph](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [Muestras de código de Microsoft ](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [Documentación de Graph de Intune](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)

## Derechos de autor
Copyright (c) 2017 Microsoft. Todos los derechos reservados.

Este proyecto ha adoptado el [Código de conducta de código abierto de Microsoft](https://opensource.microsoft.com/codeofconduct/). Para obtener más información, vea [Preguntas frecuentes sobre el código de conducta](https://opensource.microsoft.com/codeofconduct/faq/) o póngase en contacto con [opencode@microsoft.com](mailto:opencode@microsoft.com) si tiene otras preguntas o comentarios.
