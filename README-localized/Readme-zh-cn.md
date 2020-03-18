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
# Intune Graph 示例

此 PowerShell 示例脚本的存储库演示如何访问 Intune 服务资源。他们通过从 PowerShell 向 Microsoft Graph API 发出 HTTPS RESTful API 请求来证明这一点。

有关 Intune 和 Microsoft Graph 的文档，请查看[Intune Graph 文档](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)。

这些示例演示了 Intune 管理员或 Microsoft 合作伙伴管理 Intune 资源的典型操作。

下列示例包含在此存储库中：
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

在 MIT 许可下，脚本按“原样”授予许可。

#### 免责声明
部分脚本示例从 Intune 租户检索信息，其他脚本在 Intune 租户中创建、删除或更新数据。  运行前，了解每个示例脚本的影响。应使用非生产或“测试”租户帐户运行示例。 

## 使用 Intune Graph API
Intune Graph API 允许以编程方式访问租户的 Intune 信息，API 会执行 的 Intune 操作与通过 Azure 门户执行的操作相同。  

Intune 向 Microsoft Graph 提供数据的方式与其他云服务相同，具有丰富的实体信息和关系导航。  使用 Microsoft Graph 将来自其他服务和 Intune 的信息进行组合，为 IT 专业人员和最终用户构建丰富的跨服务应用程序。     

## 先决条件
使用这些 Microsoft Graph API Intune PowerShell 示例需要下列内容：
* 通过在提升的 PowerShell 命令提示符处运行 'Install-Module AzureAD' 或 'Install-Module AzureADPreview' 安装 AzureAD PowerShell 模块
* 具有生产或试用许可证，支持 Azure 门户的 Intune 租户 (https://docs.microsoft.com/en-us/intune-azure/introduction/what-is-microsoft-intune)
* 使用 Microsoft Graph APIs 来配置 Intune 控件和策略需要 Intune 许可证。
* 一个具有管理 Intune 服务权限的账户
* 适用于 Windows 10 x64 的 PowerShell v5.0（PowerShell v4.0 是正确运行脚本的最低要求）
* 注意：对于PowerShell 4.0 ，将需要 [PowershellGet Module for PS 4.0](https://www.microsoft.com/en-us/download/details.aspx?id=51451) 以启用使用安装模块功能
* 首次使用这些脚本，需要租户的全局管理员接受应用的权限

## 开始使用
安装或满足先决条件后，执行以下步骤以使用这些脚本：

#### 1.脚本使用

1. 下载存储库的内容至本地 Windows 计算机
* 提取文件至本地文件夹（如：C:\IntuneGraphSamples）
* 从开始菜单运行 PowerShell x64
* 浏览至目录（如 cd C:\IntuneGraphSamples）
* 对于本地存储库中的各文件夹，可浏览至目录并随后运行选定的脚本
* 示例应用脚本使用：
  * 如果要使用来自 C:\IntuneGraphSamples 的“管理应用脚本”，运行 "cd .\Applications\"
  * 在文件夹中运行 .\Application_MDM_Get.ps1
  以获得所有 MDM 添加的应用后，此步骤顺序可用于各文件夹....

#### 2.使用 Microsoft Graph 验证身份
首次运行这些脚本时，系统将要求提供账户，对这些服务进行身份验证：
```
Please specify your user principal name for Azure Authentication:
```
提供用户主体名称后，弹出窗口将打开密码提示。成功使用 Azure Active Directory 验证身份后，用户令牌将持续一小时，在 PowerShell 会话内一小时结束后，系统将要求重新进行身份验证。

如果首次针对租户运行脚本，弹出窗口将出现，注明：

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

注意：如果用户账户面向基于设备的条件性访问，设备必须注册或兼容，才能通过身份验证。

## 参与

如果想要参与本示例，请参阅 CONTRIBUTING.MD。

此项目已采用“Microsoft 开放源代码行为准则”。有关详细信息，请参阅“行为准则常见问题解答”。如有其他任何问题或意见，也可联系 opencode@microsoft.com。

## 问题和意见

我们乐意倾听你有关 Intune PowerShell 示例的反馈。你可通过该存储库中的“问题”部分向我们发送问题和建议。

我们非常重视你的反馈意见。请在堆栈溢出上与我们联系。使用 \[MicrosoftGraph]和 \[intune] 标记出你的问题。


## 其他资源
* [Microsoft Graph API 文档](https://developer.microsoft.com/en-us/graph/docs)
* [Microsoft Graph 门户](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [Microsoft 代码示例](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [Intune Graph 文档](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)

## 版权信息
版权所有 (c) 2017 Microsoft。保留所有权利。

此项目已采用 [Microsoft 开放源代码行为准则](https://opensource.microsoft.com/codeofconduct/)。有关详细信息，请参阅[行为准则常见问题解答](https://opensource.microsoft.com/codeofconduct/faq/)。如有其他任何问题或意见，也可联系 [opencode@microsoft.com](mailto:opencode@microsoft.com)。
