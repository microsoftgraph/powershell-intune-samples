If you use "**Connect-msgraph**" or use the ClientID “**d1ddf0e4-d672-4dae-b554-9d5bdfd93547”** in your PowerShell scripts, you need to update your ClientID.

Option 1: Migrate your old application (Microsoft Intune PowerShell) to your own application to access Graph. [Update to Microsoft Intune PowerShell example script repository on GitHub - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/intune-customer-success/update-to-microsoft-intune-powershell-example-script-repository/ba-p/3842452)

Option 2: Register app in Entra ID and give Intune Graph permission in it:

[Quickstart: Register an app in the Microsoft identity platform - Microsoft identity platform | Microsoft Learn](https://learn.microsoft.com/en-au/entra/identity-platform/quickstart-register-app)

**Steps to register Application in Entra ID to access Intune data via Graph API:**

1\. Login to **Portal.Azure.com,** select Entra ID> App registrations and click "New registration"  
<br/>2\. Enter a display name for the application and select the supported account type. Typically this will be "Accounts in this organizational directory only". This means your application is only used by users (or guests) in your tenant. For Platform, select "Public client/native (mobile & desktop)". Enter the redirect Url "**urn:ietf:wg:oauth:2.0:oob**" Then, click register.

3\. Select the App Registration page, choose your app, then click “API permissions”>"+Add a permission"> "Microsoft Graph"

4\. There are two types of permissions "Delegated permissions" and "Application permissions. For more information about permissions, see

[Overview of permissions and consent in the Microsoft identity platform - Microsoft identity platform | Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)

| Permission types | Delegated permissions | Application permissions |
| --- | --- | --- |
| Types of apps | Web / Mobile / single-page app (SPA) | Web / Daemon |
| Access context | Get access on behalf of a user | Get access without a user |
| Who can consent | \- Users can consent for their data  <br>\- Admins can consent for all users | Only admin can consent |
| Consent methods | \- Static: configured list on app registration  <br>\- Dynamic: request individual permissions at login | \- Static ONLY: configured list on app registration |

For this example, we use delegated permission and assign needed permissions to this application. Intune permissions start with DeviceManagement\*. Select the checkbox next to the required permissions, then click add permission. You need to identify the permissions required for your script actions.  It is recommended to use Read permissions if your script does not make any changes in Intune.  For example, if your script reads application information, add the DeviceManagementApps.Read.All permission.

5\. Click "Grant admin consent for &lt;companyname&gt;"

6\. To use your new Application ID, select the "Overview" page and copy your application ID. We need this id to tell our script to access it.

7\. Optional step. If your script runs with app-only authentication you need to request secrets. Click Certificates & Secrets and select New client secret. Add a Description and choose an expiration duration. Click Add to create the new client secret. Copy the client secret so it can be used by your application. It can only be viewed at creation time.

Your App registration is done.

To modify your PowerShell scripts:

**If you are using the legacy Intune PowerShell module (MsGraph)**

Add the following before the line in your script: "connect-MsGraph":

**_Update-MSGraphEnvironment -AppId {replace here with your app id}_**

Sample script for delegated access.

**_Update-MSGraphEnvironment -AppId {replace here with your app ID}_**

**_$adminUPN = Read-Host -Prompt "Enter UPN"  
$adminPwd = Read-Host -AsSecureString -Prompt "Enter password for $adminUPN"_**

$credential = New-Object System.Management.Automation.PsCredential($adminUPN, $adminPwd)

Connect-MSGraph -PSCredential $credential

If we use MSAL to access, we can replace clientId with our new application ID.

\[System.Reflection.Assembly\]::LoadFrom($adal) | Out-Null

\[System.Reflection.Assembly\]::LoadFrom($adalforms) | Out-Null

$clientId = "&lt;replace with your clientID&gt;"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "<https://graph.microsoft.com>"
