<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.


This script is used to sync all devices enrolled by all users in a specific user group.
Device group is not supported.
Based on MS Graph API: 
Invoke-DeviceManagement_ManagedDevices_SyncDevice
Get-Groups_Members

Author:
Kun Fang
#>


####################################################



function ConnectToGraph
{
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Intune) 
    {
    } 
    else {
        Write-Host "Microsoft.Graph.Intune Module does not exist, installing..."
        Install-Module -Name Microsoft.Graph.Intune
    }
    <#
    $yourUPN = "xxx.onmicrosoft.com"
    $password = ConvertTo-SecureString 'xxx' -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ($yourUPN, $password)
    

    Connect-MSGraph -PSCredential $creds
    #>
    Connect-MSGraph
}




function Get_IntuneManagedDeviceWithRetry($user_id)
{
    for ($CallCount =0; $CallCount -lt 30; $CallCount++) 
    {
        Try # graph call will sometimes return 503 service unavailable due to dense requests.
        {
            $allDeviceIDforthisUser = Get-IntuneManagedDevice | Get-MSGraphAllPages | Where-Object {$_.userId -eq "$user_id"} | select id, userId, deviceName
            return $allDeviceIDforthisUser
        }
        Catch 
        {
            Write-Host($_)
            Continue
        }
    }
    Write-Host("Calling Get_IntuneManagedDeviceWithRetry Failed!")
    return "NULL"
}



function SyncAllDevices($eachUser)
{
    $user_id = $eachUser.id
    $allDeviceIDforthisUser = Get_IntuneManagedDeviceWithRetry $user_id
    if ($allDeviceIDforthisUser -eq "NULL")
    {
        Write-Output("Error querying managed device for user: "+ $eachUser.userPrincipalName)
    }
    elseif (-Not $allDeviceIDforthisUser)
    {
        Write-Output("No enrolled device for user: "+ $eachUser.userPrincipalName)
    }
    else
    {
        foreach ($eachDevice in $allDeviceIDforthisUser)
        {
            Invoke-DeviceManagement_ManagedDevices_SyncDevice -managedDeviceId $eachDevice.id
            Write-Output("Successfully synced device: " + $eachDevice.deviceName + " of user " + $eachUser.userPrincipalName)
        }
    }
}

function main
{
    Write-Output('This is script is to sync all devices enrolled by all users in the same USER group. Written by: kufang')
    ConnectToGraph
    
    $TargetGroup = Read-Host -Prompt 'Input your Group ID'
    $groupMembers = Get-Groups_Members -groupId $TargetGroup -Select id, userPrincipalName | Get-MSGraphAllPages

    Write-Output("")

    foreach ($eachUser in $groupMembers)
    {
        SyncAllDevices $eachUser
    }

    Write-Output("")
    Read-Host 'Press Enter to exit…'
}

main



