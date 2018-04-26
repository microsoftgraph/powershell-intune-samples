# Intune Data Export Script Sample

This sample PowerShell script shows how to export all Data in Intune that is related to a specific user.

## Disclaimer

Some script samples retrieve information from your Intune tenant, and others create, delete or update data in your Intune tenant.  Understand the impact of each sample script prior to running it; samples should be run using a non-production or "test" tenant account.

Within this section there are the following scripts with the explanation of usage.

### Export-IntuneData.ps1

The script exports Intune data related to the specific user.

```PowerShell
Export-IntuneData.ps1 -Username admin@contoso.com -Upn user@contoso.com -OutputPath c:\export\user
```

Note that this script requires either the ```AzureAD``` or ```AzureADPreview``` PowerShell modules installed. To install the module you can run:

```PowerShell
Install-Module AzureAD -Scope CurrentUser
```

Here is a description of the parameter you can pass the script:

| Parameter | Required? | Description |
|-----------|-----------|-------------|
| Username | Yes | Azure AD Username for the Administrator |
| Upn | Yes | User principal name to export data for |
| IncludeAzureAD | No | Include Azure AD data in the export |
| All | No | Include all data in the export |
| OutputPath | Yes | Path to export data to |
| ExportFormat | No | Format to export data in, default value is ```json```, other supported values are ```xml``` and ```csv``` |