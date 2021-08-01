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
# Intune Graph のサンプル

この PowerShell サンプル スクリプトのリポジトリは、Intune サービス リソースにアクセスする方法を示しています。PowerShell から Microsoft Graph API に HTTPS RESTful API 要求を行うことにより、その方法を示します。

Intune および Microsoft Graph のドキュメントについては、「[Intune Graph のドキュメント](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)」を参照してください。

これらのサンプルでは、一般的な Intune 管理者、または Intune リソースを管理するための Microsoft パートナーの操作を示します。

このリポジトリには、次のサンプルが含まれています:
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

スクリプトは、MIT ライセンスの下、 "現状有姿" でライセンス付与されます。

#### 免責事項
一部のスクリプトサンプルでは、Intune テナントから情報を取得ます。また、他のスクリプト サンプルでは、Intune テナントでデータを作成、削除、更新します。  実行前に、各サンプルスクリプトの影響を理解してください。サンプルは、非運用テナント アカウントまたは "テスト" テナントアカウントを使用して実行する必要があります。 

## Intune Graph API の使用
Intune Graph API を使用すると、テナントの Intune の情報へのプログラムによるアクセスが可能となります。API は Azure Portal で使用できるものと同じ Intune 操作を実行します。  

Intune は、豊富なエンティティ情報とリレーションシップのナビゲーションを使用して、他のクラウド サービスと同じ方法で Microsoft Graph にデータを提供します。  Microsoft Graph を使用して、他のサービスからの情報と Intune を結合し、IT プロフェッショナルやエンド ユーザー向けの豊富なサービス間アプリケーションをビルドします。     

## 前提条件
これらの Microsoft Graph API Intune PowerShell のサンプルを使用するには、以下が必要です。
* 管理者特権の PowerShell プロンプトから「Install-Module AzureAD」または「Install-Module AzureADPreview」を実行して、AzureAD PowerShell モジュールをインストールすること
* 本番ライセンスまたは試用ライセンスで Azure Portal をサポートする Intune テナント (https://docs.microsoft.com/en-us/intune-azure/introduction/what-is-microsoft-intune)
* Microsoft Graph API を使用して Intune 制御とポリシーを構成するには、Intune ライセンスが必要です。
* Intune サービスを管理する権限を持つアカウント
* Windows 10 x64 上の PowerShell v5.0 (PowerShell v4.0 は、スクリプトが正しく機能するための最小要件です)
* 注:PowerShell 4.0 の場合、インストール モジュール機能の使用を可能にするために [PS 4.0 用PowershellGet モジュール](https://www.microsoft.com/en-us/download/details.aspx?id=51451)が必要です
* これらのスクリプトを初めて使用するために、テナントのグローバル管理者がアプリケーションのアクセス許可を受け入れる必要があります

## はじめに
前提条件をインストールした後、または前提条件を満たした後、次の手順を実行して、これらのスクリプトを使用します。

#### 1.スクリプトの使用方法

1. ローカル Windows マシンにリポジトリのコンテンツをダウンロードします
* ローカル フォルダー (例: C:\IntuneGraphSamples) にファイルを抽出します
* スタート メニューで PowerShell x64 を実行します
* ディレクトリ (例: cd C:\IntuneGraphSamples) を参照します
* ローカル リポジトリ内のフォルダーごとに、そのディレクトリを参照し、選択したスクリプトを実行できます。
* アプリケーション スクリプトの使用例:
  * Manage Applications スクリプトを実行するには、C:\IntuneGraphSamples から、"cd .\Applications\" を実行します
  * フォルダーで .\Application_MDM_Get.ps1
  を実行し、すべての MDM 追加アプリケーションを取得します。この手順のシーケンスは、各フォルダーで使用できます。

#### 2.Microsoft Graph で認証する
これらのスクリプトを初めて実行するときに、サービスで認証するアカウントを指定するように求められます。
```
Please specify your user principal name for Azure Authentication:
```
ユーザー プリンシパル名を入力すると、パスワードの入力を求めるメッセージが表示されます。Azure Active Directory で正常に認証された後、ユーザー トークンは1時間後に、PowerShell セッション内で有効期限が切れると、再認証を求められます。

テナントに対して初めてスクリプトを実行する場合は、以下のメッセージが表示されます。

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

注:ユーザー アカウントがデバイス ベースの条件付きアクセスを対象としている場合は、認証させるために、デバイスを登録するか、準拠する必要があります。

## 投稿

このサンプルに投稿する場合は、CONTRIBUTING.MD を参照してください。

このプロジェクトでは、Microsoft オープン ソース倫理規定が採用されています。詳細については、「倫理規定の FAQ」を参照してください。また、その他の質問やコメントがあれば、opencode@microsoft.com までお問い合わせください。

## 質問とコメント

PowerShell のサンプルに関するフィードバックをお寄せください。質問や提案は、このリポジトリの「問題」セクションで送信できます。

お客様からのフィードバックを重視しています。スタック オーバーフローでご連絡ください。質問には [MicrosoftGraph] と [intune] でタグ付けしてください。


## その他のリソース
* [Microsoft Graph API ドキュメント](https://developer.microsoft.com/en-us/graph/docs)
* [Microsoft Graph ポータル](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [Microsoft コード サンプル](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [Intune Graph ドキュメント](https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/intune_graph_overview)

## 著作権
Copyright (c) 2017 Microsoft.All rights reserved.

このプロジェクトでは、[Microsoft オープン ソース倫理規定](https://opensource.microsoft.com/codeofconduct/) が採用されています。詳細については、「[Code of Conduct の FAQ (倫理規定の FAQ)](https://opensource.microsoft.com/codeofconduct/faq/)」を参照してください。また、その他の質問やコメントがあれば、[opencode@microsoft.com](mailto:opencode@microsoft.com) までお問い合わせください。
