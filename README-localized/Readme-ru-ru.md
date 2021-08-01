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
# Примеры для Intune Graph

Этот репозиторий примеров скриптов PowerShell демонстрирует, как получать доступ к ресурсам службы Intune. Для этого совершаются HTTPS-запросы RESTful API к API Microsoft Graph из PowerShell.

Документация для Intune и Microsoft Graph можно найти здесь [документации Intune Graph](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview).

Эти примеры демонстрируют типичные действия администратора Intune или партнера Microsoft по управлению ресурсами Intune.

Следующие примеры включены в этот репозиторий:
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

Скрипты лицензируются «как есть». под лицензией MIT.

#### Заявление об отказе
Некоторые образцы сценариев получают информацию от вашего клиента Intune, а другие создают, удаляют или обновляют данные в вашем клиенте Intune.  Понять влияние каждого примера сценария до его запуска; образцы должны быть запущены с использованием непроизводственного или «тестового» счета арендатора. 

## Использование API Graph для Intune
API-интерфейс Intune обеспечивает программный доступ к информации Intune для вашего клиента, и API выполняет те же операции Intune, что и через портал Azure.  

Intune предоставляет данные в Microsoft Graph так же, как и другие облачные сервисы, с богатой информацией об объектах и навигацией по отношениям.  Используйте Microsoft Graph для объединения информации из других служб и Intune для создания многофункциональных межсервисных приложений для ИТ-специалистов или конечных пользователей.     

## Предварительные требования
Для использования этих примеров Microsoft Graph API Intune PowerShell требуется следующее:
* Установите модуль AzureAD PowerShell, запустив «Install-Module AzureAD» или «Install-Module AzureADPreview» из командной строки PowerShell с повышенными привилегиями.
* Клиент Intune, который поддерживает портал Azure с помощью производственная или пробная лицензия (https://docs.microsoft.com/en-us/intune-azure/introduction/what-is-microsoft-intune)
* Для использования API-интерфейсов Microsoft Graph для настройки элементов управления и политик Intune требуется лицензия Intune.
* Учетная запись с разрешениями на администрирование службы Intune.
* PowerShell v5.0 в Windows 10 x64 (PowerShell v4.0 является минимальным требованием для правильной работы сценариев).
* Примечание. В PowerShell 4,0 для работы с приложением PowerShell необходимо использовать модуль [PowershellGet для PS 4,0](https://www.microsoft.com/en-us/download/details.aspx?id=51451), позволяющий использовать функциональные возможности модуля
* при первом использовании этих сценариев необходимо, чтобы глобальный администратор клиента принимал разрешения приложения.

## Начало работы
После того, как предварительные условия установлены или выполнены, выполните следующие шаги для использования этих сценариев:

#### 1. Использование сценария

1. Загрузите содержимое репозитория на локальный компьютер с Windows
* Извлечение файлов в локальную папку (например, C:\IntuneGraphSamples)
* Запустите PowerShell x64 из меню «Пуск»
* Перейдите в каталог (например, cd C:\IntuneGraphSamples).
* Для каждой папки в локальном репозитории вы можете перейти к этому каталогу, а затем запустить скрипт на ваш выбор
* Пример использования скрипта приложения:
  * Чтобы использовать сценарии управления приложениями, в C:\IntuneGraphSamples, run "cd .\Applications\"
  * Попав в папку, запустите.\Application_MDM_Get.ps1,
  чтобы получить все приложения, добавленные в MDM. Эту последовательность шагов можно использовать для каждой папки ....

#### 2. Аутентификация с помощью Microsoft Graph
При первом запуске этих сценариев вам будет предложено предоставить учетную запись для аутентификации в службе:
```
Please specify your user principal name for Azure Authentication:
```
После того, как вы предоставите имя пользователя, откроется всплывающее окно с запросом вашего пароля. После успешной проверки подлинности с помощью Azure Active Directory токен пользователя будет действовать в течение часа, а по истечении часа в сеансе PowerShell вам будет предложено пройти повторную проверку подлинности.

Если вы в первый раз запускаете скрипт для своего арендатора, появится всплывающее окно с указанием:

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

Примечание. Если ваша учетная запись предназначена для условного доступа на основе устройства, ваше устройство должно быть зарегистрировано или соответствовать требованиям для прохождения аутентификации.

## Участие

Если вы хотите внести свой вклад в этот образец, см. CONTRIBUTING.MD.

В этом проекте принят кодекс поведения Microsoft с открытым исходным кодом. Для получения дополнительной информации см. FAQ по Кодексу поведения или свяжитесь с opencode@microsoft.com с любыми дополнительными вопросами или комментариями.

## Вопросы и комментарии

Мы хотели бы получить ваши отзывы о образце Intune PowerShell. Вы можете присылать нам свои вопросы и предложения в разделе «Проблемы» этого репозитория.

Ваш отзыв важен для нас. Для связи с нами используйте сайт Stack Overflow. Отметьте свои вопросы с помощью \[MicrosoftGraph] и \[intune].


## Дополнительные ресурсы
* [Документация по Microsoft Graph API](https://developer.microsoft.com/en-us/graph/docs)
* [Портал Microsoft Graph](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [Примеры программного кода Майкрософт](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [Документация Intune Graph](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)

## Авторские права
(c) Корпорация Майкрософт (Microsoft Corporation), 2017. Все права защищены.

Этот проект соответствует [Правилам поведения разработчиков открытого кода Майкрософт](https://opensource.microsoft.com/codeofconduct/). Дополнительные сведения см. в разделе [часто задаваемых вопросов о правилах поведения](https://opensource.microsoft.com/codeofconduct/faq/). Если у вас возникли вопросы или замечания, напишите нам по адресу [opencode@microsoft.com](mailto:opencode@microsoft.com).
