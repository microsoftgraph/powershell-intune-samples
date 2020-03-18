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
# Exemplos de Gráficos do Intune

Este repositório de exemplos de scripts do PowerShell mostra como acessar os recursos de serviços do Intune. Eles demonstram isso por meio de solicitações da API RESTful HTTPS à API do Microsoft Graph do PowerShell.

É possível encontrar a documentação do Intune e do Microsoft Graph aqui [Documentação do Graph para Intune](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

Esses exemplos mostram o administrador típico do Intune ou ações de parceiros da Microsoft para o gerenciamento de recursos do Intune.

Os exemplos a seguir estão incluídos neste repositório:
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

Os scripts são licenciados no estado em que se encontram sob a Licença MIT.

#### Aviso de isenção de responsabilidade
Algumas amostras de script recuperam informações de seu locatário do Intune e outras criam, excluem ou atualizam dados no locatário do Intune.  Compreenda o impacto de cada script de exemplo antes de executá-lo. Os exemplos devem ser executados usando uma conta de locatário de teste ou que não seja de produção. 

## Uso da API do Graph para Intune
A API do Graph para Intune permite o acesso programático a informações do Intune para seu locatário; a API executa as mesmas operações do Intune disponibilizadas pelo Portal do Azure.  

O Intune fornece dados para o Microsoft Graph da mesma forma que outros serviços de nuvem fazem, com informações avançadas sobre entidades e navegação de relacionamentos.  Use o Microsoft Graph para combinar informações de outros serviços e do Intune e criar aplicativos avançados com serviços variados para profissionais de TI ou usuários finais.     

## Pré-requisitos
O uso desses exemplos do PowerShell para o Intune na API do Microsoft Graph exige o seguinte:
* Instale o módulo de PowerShell do AzureAD executando "Install-Module AzureAD" ou "Install-Module AzureADPreview" em um prompt de PowerShell elevado
* Um locatário do Intune que suporte o Portal do Azure com uma licença de produção ou de avaliação (https://docs.microsoft.com/en-us/intune-azure/introduction/what-is-microsoft-intune)
* Usar as APIs do Microsoft Graph para configurar os controles e políticas do Intune requer uma licença do Intune
* Uma conta com permissões para administrar o serviço do Intune
* PowerShell v 5.0 no Windows 10 x64 (o PowerShell v 4.0 é o requisito mínimo para os scripts funcionarem corretamente)
* Observação: Para o PowerShell 4.0, você precisará do [Módulo PowershellGet para PS 4.0](https://www.microsoft.com/en-us/download/details.aspx?id=51451) a fim de habilitar o uso da funcionalidade Install-Module
* A primeira utilização desses scripts exige que um Administrador Global do Locatário aceite as permissões do aplicativo

## Introdução
Após instalar ou atender aos pré-requisitos, execute as etapas a seguir para usar esses scripts:

#### 1. Uso de script

1. Baixe o conteúdo do repositório para o seu computador local com Windows
* Extraia os arquivos em uma pasta local (por exemplo, C:\IntuneGraphSamples)
* Execute o PowerShell x64 no menu Iniciar
* Navegue até o diretório (por exemplo, cd C:\IntuneGraphSamples)
* Você pode navegar em cada pasta do repositório local e executar o script de sua escolha
* Exemplo de uso de script de aplicativo:
  * Para usar os scripts para Gerenciar Aplicativos em C:\IntuneGraphSamples, execute "cd .\Applications\"
  * Quando estiver na pasta, execute .\Application_MDM_Get.ps1
  para obter todos os aplicativos MDM adicionados. Essa sequência de etapas pode ser usada em cada pasta.

#### 2. Autenticação com o Microsoft Graph
Na primeira vez que executar estes scripts, você será solicitado a fornecer uma conta para autenticação com o serviço:
```
Please specify your user principal name for Azure Authentication:
```
Depois de fornecer o nome principal do usuário, um pop-up será aberto para solicitar sua senha. Após uma autenticação bem-sucedida com o Azure Active Directory, o token de usuário dura por uma hora e, quando a hora expirar dentro da sessão do PowerShell, será solicitada uma nova autenticação.

Se você estiver executando o script pela primeira vez em seu locatário, um pop-up será apresentado:

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

Observação: Se sua conta de usuário se destina ao acesso condicional baseado em dispositivo, seu dispositivo deve estar registrado ou em conformidade para passar na autenticação.

## Colaboração

Se quiser contribuir para esse exemplo, confira CONTRIBUTING.MD.

Este projeto adotou o Código de Conduta do Código Aberto da Microsoft. Para saber mais, confira as Perguntas frequentes sobre o Código de Conduta ou contate opencode@microsoft.com se tiver outras dúvidas ou comentários.

## Perguntas e comentários

Gostaríamos de saber a sua opinião sobre o exemplo de PowerShell do Intune. Você pode enviar perguntas e sugestões na seção Questões deste repositório.

Seus comentários são importantes para nós. Junte-se a nós na página do Stack Overflow. Marque as suas perguntas com \[MicrosoftGraph] e \[Inture].


## Recursos adicionais
* [Documentação da API do Microsoft Graph](https://developer.microsoft.com/en-us/graph/docs)
* [Portal do Microsoft Graph](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [Exemplos de códigos da Microsoft](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [Documentação do Graph para Intune](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)

## Direitos autorais
Copyright (c) 2017 Microsoft. Todos os direitos reservados.

Este projeto adotou o [Código de Conduta de Código Aberto da Microsoft](https://opensource.microsoft.com/codeofconduct/).  Para saber mais, confira as [Perguntas frequentes sobre o Código de Conduta](https://opensource.microsoft.com/codeofconduct/faq/) ou entre em contato pelo [opencode@microsoft.com](mailto:opencode@microsoft.com) se tiver outras dúvidas ou comentários.
