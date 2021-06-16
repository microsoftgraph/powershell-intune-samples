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
# Exemples Intune Graph

Ce référentiel d’exemples de scripts PowerShell présente comment accéder aux ressources du service Intune. Les exemples illustrent l'envoi de demandes d’API RESTful HTTPS à l’API Microsoft Graph à partir de PowerShell.

La documentation sur Intune et Microsoft Graph est disponible ici [Documentation Intune Graph](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

Ces exemples illustrent des actions classiques d'administrateurs Intune ou de partenaires Microsoft pour la gestion des ressources Intune.

Les exemples suivants sont inclus dans le référentiel :
-AdminConsent
-AndroidEnterprise
-AppleEnrollment
-applications
-ApplicationSync
-AppProtectionPolicy
-Auditing
-Authentication
-CertificationAuthority
-CheckStatus
-CompanyPortalBranding
-CompliancePolicy
-CorporateDeviceEnrollment
-DeviceConfiguration
-EnrollmentRestrictions
-IntuneDataExport
-LOB_Application
-ManagedDevices
-pagination
-RBAC
-RemoteActionAudit
-SoftwareUpdates
-TermsAndConditions
-UserPolicyReport

Les scripts sont sous licence « en l'état » sous la Licence MIT.

#### Clause d’exclusion de responsabilité
Certains exemples de script récupèrent des informations de votre client Intune, alors que d’autres créent, suppriment ou mettent à jour des données dans votre client Intune.  Veuillez comprendre l’influence de chaque exemple de script avant de l’exécuter ; les exemples doivent être exécutés à l’aide d’un compte client non productif ou en « test ». 

## Utilisation de l’API Graph Intune
L’API de Microsoft Graph pour Intune permet l’accès programmatique aux informations Intune relatives à votre client ; l’API effectue les mêmes opérations Intune que celles disponibles via le Portail Azure.  

Intune fournit des données dans Microsoft Graph Intune de la même façon que d’autres services cloud, avec des informations d’identité enrichies et une navigation des relations.  Utilisez Microsoft Graph pour combiner les informations provenant d’autres services et d’Intune et créer des applications interservices enrichies pour les professionnels de l’informatique ou des utilisateurs finaux.     

## Conditions préalables
Pour utiliser les exemples d’API Intune PowerShell de Microsoft Graph, les éléments suivants sont nécessaires :
* installer le module AzureAD PowerShell en exécutant « Install-Module AzureAD » ou « Install-Module AzureADPreview » à partir d’une invite PowerShell avec élévation de privilèges
* Un client Intune qui prend en charge le Portail Azure avec une licence de production ou d’évaluation (https://docs.microsoft.com/en-us/intune-azure/introduction/what-is-microsoft-intune)
* Une licence Intune est nécessaire pour l'utilisation des API Microsoft pour configurer les stratégies et les contrôles
* Un compte disposant des autorisations pour administrer le service Intune
* PowerShell v5.0 sur Windows 10 x64 (PowerShell v4.0 est une condition minimale requise pour que les scripts fonctionnent correctement)
* Remarque : Pour PowerShell 4.0, vous aurez besoin du [Module PowershellGet pour PS 4.0](https://www.microsoft.com/en-us/download/details.aspx?id=51451) pour activer l’utilisation de la fonctionnalité Install-Module
* La première utilisation de ces scripts nécessite l'acceptation des autorisations d'application par un administrateur général du client.

## Prise en main
Une fois que vous avez installé ou rempli les conditions préalables, procédez comme suit pour utiliser ces scripts :

#### 1. Utilisation de script

1. Téléchargez le contenu du référentiel sur votre ordinateur Windows local
* Faites une extraction des fichiers dans un dossier local (par exemple, C:\IntuneGraphSamples)
* Exécutez PowerShell x64 dans le menu de démarrage
* Accédez au répertoire (par exemple, CD C:\IntuneGraphSamples)
* Pour chaque Dossier du référentiel local, vous pouvez accéder à ce répertoire, puis exécuter le script de votre choix.
* Exemple d’utilisation du script d’application :
  * Pour utiliser les scripts Gérer les applications, à partir de C:\IntuneGraphSamples, exécutez « cd .\Applications\ »
  * Une fois dans le dossier, exécutez \Application_MDM_Get.ps1
  pour obtenir toutes les applications ajoutées. Cette série d’étapes peut être utilisée pour chaque dossier....

#### 2. Authentification d’application à l'aide de Microsoft Graph
Lorsque vous exécutez ces scripts pour la première fois, vous êtes invité à fournir un compte pour vous authentifier auprès du service :
```
Please specify your user principal name for Azure Authentication:
```
Une fois que vous avez fourni un nom d’utilisateur principal, une fenêtre contextuelle s’ouvre et vous invite à saisir votre mot de passe. Une fois l’authentification réussie avec Azure Active Directory, le jeton d’utilisateur est valable pendant une heure. Au-delà de cette heure au sein de la session PowerShell, vous êtes invité à vous authentifier de nouveau.

Si vous exécutez le script pour la première fois chez votre client, une fenêtre contextuelle s’affiche indiquant :

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

Remarque : Si votre compte utilisateur est ciblé pour l’accès conditionnel basé sur l’appareil, votre appareil doit être inscrit ou être conforme pour réussir l’authentification.

## Contribution

Si vous souhaitez contribuer à cet exemple, voir CONTRIBUTING.MD.

Ce projet a adopté le Code de conduite Open Source de Microsoft. Pour plus d'informations, reportez-vous à la FAQ relative au Code de conduite ou contactez opencode@microsoft.com pour toute question ou tout commentaire.

## Questions et commentaires

Nous serions ravis de connaître votre opinion sur l’exemple Intune PowerShell. Vous pouvez nous faire part de vos questions et suggestions dans la rubrique problèmes de ce référentiel.

Votre avis compte beaucoup pour nous. Communiquez avec nous sur Stack Overflow. Posez vos questions avec les tags [MicrosoftGraph] et [Intune].


## Ressources supplémentaires
* [Documentation de l’API Microsoft Graph](https://developer.microsoft.com/en-us/graph/docs)
* [Portail Microsoft Graph](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [Exemple de codes Microsoft](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [Documentation d'Intune Graph](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)

## Copyright
Copyright (c) 2017 Microsoft. Tous droits réservés.

Ce projet a adopté le [code de conduite Open Source de Microsoft](https://opensource.microsoft.com/codeofconduct/). Pour en savoir plus, reportez-vous à la [FAQ relative au code de conduite](https://opensource.microsoft.com/codeofconduct/faq/) ou contactez [opencode@microsoft.com](mailto:opencode@microsoft.com) pour toute question ou tout commentaire.
