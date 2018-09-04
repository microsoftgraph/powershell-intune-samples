Function Get-InstallStatusForApp
{
<#
.SYNOPSIS
This function will get the installation status of an application given the application's ID.
.DESCRIPTION
If you want to track your managed intune application installaion stats as you roll them out in your environment, use this commandlet to get the insights.
.EXAMPLE
Get-InstallStatusForApp -Name a1a2a-b1b2b3b4-c1c2c3c4
This will return the installation status of the application with the ID of a1a2a-b1b2b3b4-c1c2c3c4
.NOTES
NAME: Get-InstallStatusForApp
#>
	
	[cmdletbinding()]
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$AppId
	)
	
	$graphApiVersion = "Beta"
	$Resource = "deviceAppManagement/mobileApps/$AppId/installSummary"
	
	try
	{

		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
	}
	
}
