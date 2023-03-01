param(
    [Parameter(Mandatory)]
    [String] $ConfigurationDataFile
) 

$WelcomeMessage="Welcome to the Azure Stack HCI 2 Node Deployment script, this script will deploy out a fully functional 2 Node Azure Stack HCI Cluster, in a Switchless configuraiton. The first step in this deployment is to ask for you to sign into your Azure Subscription."
#Begin Function Region

Function Update-Progress 
{
    $progressLog[$currentStepIndex] = "$currentStepName = Completed"
    $progressLog | Out-File -FilePath '.\progress.log' -Encoding utf8 -Force
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Completed Step:"(($progressLog[$currentStepIndex]).Split())[0] -ForegroundColor DarkGreen
    Write-Host "Next Step:"(($progressLog[$currentStepIndex+1]).Split())[0] -ForegroundColor DarkGreen

}
        
function LoadVariables {
   
    #Set Variables from Config File

$config=Import-PowerShellDataFile -Path $ConfigurationDataFile 
Write-Host -ForegroundColor Green -Object $WelcomeMessage
return $config 
}

function RetrieveCredentials{
param ()
$azlogin = Connect-AzAccount -Subscription $config.azuresubid 
Select-AzSubscription -Subscription $config.AzureSubID
#Set AD Domain Cred
$AzDJoin = Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "DomainJoinerSecret"
$ADcred = [pscredential]::new("fc\djoin",$AZDJoin.SecretValue)
#$ADpassword = ConvertTo-SecureString "" -AsPlainText -Force
#$ADCred = New-Object System.Management.Automation.PSCredential ("contoso\djoiner", $ADpassword)

#Set Cred for AAD tenant and subscription
$AADAccount = "azstackadmin@azurestackdemo1.onmicrosoft.com"
$AADAdmin=Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "azurestackadmin"
$AADCred = [pscredential]::new("azstackadmin@azurestackdemo1.onmicrosoft.com",$AADAdmin.SecretValue)
$Arcsecretact=Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "ArcSPN"
$ARCSecret=$arcsecretact.SecretValue
#$ARCSPN=[pscredential]::new("92ba32da-56d0-449d-b6e3-9d1c64b88a19",$ARCSecret.SecretValue) 
}





function ConfigureWorkstation {
    param ()
    Write-Host -ForegroundColor Green -Object "Configuring Managment Workstation"

    #Set WinRM for remote management of nodes
    #winrm quickconfig
    Enable-WSManCredSSP -Role Client -DelegateComputer * -Force
    New-Item hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly
    New-ItemProperty hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value "wsman/*" -Force 

    Write-Host -ForegroundColor Green -Object "Installing Required Features on Management Workstation"

    If ((get-computerinfo).windowsinstallationtype -eq "client"){
        Enable-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V-Management-PowerShell"  -Online 
        }
        
        else {
        #Install some PS modules if not already installed
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools;
        Install-Module AZ.ConnectedMachine -force
        Set-TimeZone -Name "Central Standard Time" 
        $ProgressPreference = 'SilentlyContinue'; 
        Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; 
        Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi
        }


}

function ConfigureNodes {
    param ()
    Write-Host -ForegroundColor Green "Configuring Nodes"

#Add features, add PS modules, rename, join domain, reboot
Invoke-Command -ComputerName $ServerList -Credential $ADCred -ScriptBlock {
    Install-WindowsFeature -Name "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-Powershell","FS-Data-Deduplication", "Storage-Replica", "NetworkATC", "System-Insights" -IncludeAllSubFeature -IncludeManagementTools
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name Az.StackHCI -Force -All
    Enable-WSManCredSSP -Role Server -Force
    New-NetFirewallRule -DisplayName “ICMPv4” -Direction Inbound -Action Allow -Protocol icmpv4 -Enabled True
    Enable-NetFirewallRule -DisplayGroup “Remote Desktop”
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0
    Set-TimeZone -Name "Central Standard Time" 
    $ProgressPreference = 'SilentlyContinue'; 
    Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; 
    Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi
}
     
Restart-Computer -ComputerName $ServerList -Protocol WSMan -Wait -For PowerShell -Force

#Pause for a bit - let changes apply before moving on...
Start-Sleep 180
    
}

function ConfigureNode01 {
    param ()
    Write-Host -ForegroundColor Green -Object "Configure Node 01"

Invoke-Command -ComputerName $config.Node01 -Credential $ADCred -ScriptBlock {

# Configure IP and subnet mask, no default gateway for Storage interfaces
   
    #Rename Net Adapters
    $m1=Get-NetAdapter -InterfaceDescription "Intel(R) Ethernet Connection X722 for 10GBASE-T"
    $m2=Get-NetAdapter -InterfaceDescription "Intel(R) Ethernet Connection X722 for 10GBASE-T #2"
    $m1 | Rename-NetAdapter -NewName "MGMT1"
    $m2 | Rename-NetAdapter -NewName "MGMT2"
    $s1=Get-NetAdapter -InterfaceDescription "Mellanox ConnectX-6 Dx Adapter"
    $s2=Get-NetAdapter -InterfaceDescription "Mellanox ConnectX-6 Dx Adapter #2"
    $s1 | Rename-NetAdapter -NewName "SMB1"
    $s2 | Rename-NetAdapter -NewName "SMB2"
    
    #MGMT
    New-NetIPAddress -InterfaceAlias "MGMT" -IPAddress $using:config.node01_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP  | Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    
    #Storage 
    
    New-NetIPAddress -InterfaceAlias "SMB1" -IPAddress 172.16.0.1 -PrefixLength 24
    New-NetIPAddress -InterfaceAlias "SMB2" -IPAddress 172.16.1.1 -PrefixLength 24
    #Get-NetAdapter "-Name Ethernet *"| Disable-NetAdapter -Confirm:$false
}
}

function ConfigureNode02 {
    param ()
    Write-Host -ForegroundColor Green -Object "Configure Node02"

Invoke-Command -ComputerName $config.Node02 -Credential $ADCred -ScriptBlock {
    # Configure IP and subnet mask, no default gateway for Storage interfaces
    
    #Rename Net Adapters
    $m1=Get-NetAdapter -InterfaceDescription "Intel(R) Ethernet Connection X722 for 10GBASE-T"
    $m2=Get-NetAdapter -InterfaceDescription "Intel(R) Ethernet Connection X722 for 10GBASE-T #2"
    $m1 | Rename-NetAdapter -NewName "MGMT1"
    $m2 | Rename-NetAdapter -NewName "MGMT2"
    $s1=Get-NetAdapter -InterfaceDescription "Mellanox ConnectX-6 Dx Adapter"
    $s2=Get-NetAdapter -InterfaceDescription "Mellanox ConnectX-6 Dx Adapter #2"
    $s1 | Rename-NetAdapter -NewName "SMB1"
    $s2 | Rename-NetAdapter -NewName "SMB2"
    
    
    #MGMT
    New-NetIPAddress -InterfaceAlias "MGMT" -IPAddress $using:config.node02_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP| Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    
    #Storage 
    New-NetIPAddress -InterfaceAlias "SMB1" -IPAddress 172.16.0.2 -PrefixLength 24
    New-NetIPAddress -InterfaceAlias "SMB2" -IPAddress 172.16.1.2 -PrefixLength 24
    #Get-NetAdapter -Name "Ethernet *" | Disable-NetAdapter -Confirm:$false
}
}

function PrepareStorage {
    param ()
    Write-Host -ForegroundColor Green -Object "Prepare Storage"

#Clear Storage
Invoke-Command ($ServerList) {
    Update-StorageProviderCache
    Get-StoragePool | ? IsPrimordial -eq $false | Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
    Get-StoragePool | ? IsPrimordial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
    Get-StoragePool | ? IsPrimordial -eq $false | Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue
    Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
    Get-Disk | ? Number -ne $null | ? IsBoot -ne $true | ? IsSystem -ne $true | ? PartitionStyle -ne RAW | % {
        $_ | Set-Disk -isoffline:$false
        $_ | Set-Disk -isreadonly:$false
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
        $_ | Set-Disk -isreadonly:$true
        $_ | Set-Disk -isoffline:$true
    }
    Get-Disk | Where Number -Ne $Null | Where IsBoot -Ne $True | Where IsSystem -Ne $True | Where PartitionStyle -Eq RAW | Group -NoElement -Property FriendlyName
} | Sort -Property PsComputerName, Count
}

function PrepareClusterPermissions {
    param ( [string]$OuPath)
    Import-Module ActiveDirectory

    #ACL & ACLPath
    $ACLPath = "AD:\\"+$OuPath
    $ACL = Get-Acl "$ACLPath" -ErrorAction Stop
    
    #Account getting the permissions granted TO (Identity of the Cluster)
    $computer = Get-ADComputer $config.ClusterName -ErrorAction Stop
    $sid = [System.Security.Principal.SecurityIdentifier] $computer.SID
    $ClusterIdentity = [System.Security.Principal.IdentityReference] $SID
    
    #Part 1 = Create & Delete Child Objects (for "Computer" objects only)
    #1. Find the "Computers" Object type [NOTE: I'm 99% sure this is always "bf967a86-0de6-11d0-a285-00aa003049e2", but couldn't find MS documentation saying so
    $ComputerObject = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {Name -eq "computer"} -Properties SchemaIdGuid -ErrorAction Stop
    $ComputerObjectType = [GUID]$ComputerObject.SchemaIdGuid
    #2. Allow on create child & delete child (w/no inheritance)
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild, DeleteChild"
    $AccessControlType = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
    #3. Set the rule
    $ChildComputersRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ClusterIdentity, $adRights, $AccessControlType, $ComputerObjectType, $inheritanceType -ErrorAction Stop
    #4. Add Access Rule to the ACL
    $ACL.AddAccessRule($ChildComputersRule)
    
}

function CreateCluster {
    param ()
    Write-Host -ForegroundColor Green -Object "Creating the Cluster"

#Create the Cluster
Invoke-Command -ComputerName $config.node01 -Credential $adcred -Authentication Credssp -ScriptBlock {
#Test-Cluster –Node $using:config.Node01, $using:config.Node02 –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"
New-Cluster -Name $using:config.ClusterName -Node $using:config.Node01, $using:config.Node02 -StaticAddress $using:config.ClusterIP -NoStorage -AdministrativeAccessPoint ActiveDirectoryAndDns 

#Pause for a bit then clear DNS cache.
Start-Sleep 30
Clear-DnsClientCache

# Update the cluster network names that were created by default.  First, look at what's there
Get-ClusterNetwork -Cluster $using:config.ClusterName  | ft Name, Role, Address

# Change the cluster network names so they are consistent with the individual nodes
(Get-ClusterNetwork -Cluster $using:config.ClusterName  | where-object address -like "172.16.0.0").Name = "Storage1"
(Get-ClusterNetwork -Cluster $using:config.ClusterName  | where-object address -like "172.16.1.0").Name = "Storage2"
#(Get-ClusterNetwork -Cluster $using:config.ClusterName  | where-object address -like "").Name = "OOB"
(Get-ClusterNetwork -Cluster $using:config.ClusterName  | where-object address -like $using:config.MGMTSubnet).Name = "MGMT"

# Check to make sure the cluster network names were changed correctly
Get-ClusterNetwork -Cluster $config.ClusterName | ft Name, Role, Address
}

}

function SetLiveMigration {
    param()
    Write-Host -ForegroundColor Green -Object "Set Cluster Live Migration Settings"

#Set Cluster Live Migration Settings 
Enable-VMMigration -ComputerName $ServerList
Add-VMMigrationNetwork -computername $ServerList -Subnet 172.16.0.0/24 -Priority 1 
Add-VMMigrationNetwork -computername $ServerList -Subnet 172.16.1.0/24 -Priority 2 
Set-VMHost -ComputerName $ServerList -MaximumStorageMigrations 2 -MaximumVirtualMachineMigrations 2 -VirtualMachineMigrationPerformanceOption SMB -UseAnyNetworkForMigration $false 

}

function DeployS2D {
    param ()
    Write-Host -ForegroundColor Green -Object "Enable Storage Spaces Direct"

#Enable S2D
Enable-ClusterStorageSpacesDirect  -CimSession $config.ClusterName -PoolFriendlyName $config.StoragePoolName -Confirm:0 

}

function EnableCAU {
param()
#############Enable CAU and update to latest 21H2 bits...###############
#First we must add the AD cluster object to the Cluster Objects AD Group
$ADClusterObj = $config.ClusterName + "$"
Add-ADGroupMember -Identity ClusterObjects -Members $ADClusterObj
#Now we can add the CAU role...
Add-CauClusterRole -ClusterName $config.ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose


#Enable KSR on ALl and Future CAU 
Get-Cluster -Name $config.ClusterName | Set-ClusterParameter -Name CauEnableSoftReboot -Value 1 -Create

#Now we can force an update...
Invoke-CauRun -ClusterName $config.ClusterName -CauPluginName "Microsoft.WindowsUpdatePlugin" -MaxFailedNodes 1 -MaxRetriesPerNode 3 -RequireAllNodesOnline -Force


}

function ConfirmFunctionLevels {
    param ()
    #Update Cluster Function Level

$cfl=Get-Cluster -Name $config.ClusterName 
if ($cfl.ClusterFunctionalLevel -lt "11") {
write-host -ForegroundColor yellow -Object "Cluster Functional Level needs to be upgraded"  

Update-ClusterFunctionalLevel -Cluster $config.ClusterName -Verbose -Force
}

else {
write-host -ForegroundColor Green -Object "Cluster Functional Level is good"

}

#storage Pool Level check and upgrade

$spl=Get-StoragePool -CimSession $config.ClusterName -FriendlyName $config.StoragePoolName
 
if ($spl.version -ne "Windows Server 2022") {
write-host -ForegroundColor yellow -Object "Storage Pool Level needs to be upgraded"

Update-StoragePool -FriendlyName $config.StoragePoolName -Confirm:0 -CimSession $config.Node01
}
else {
write-host -ForegroundColor Green -Object "Storage Pool level is set to Windows Server 2022"
}
    
}

function CreateCSV {
    param ()
    write-host -ForegroundColor Green -Object "Creating Cluster Shared Volume"

#Create S2D Tier and Volumes
New-StorageTier -StoragePoolFriendlyName $config.StoragePoolName -FriendlyName 2WayNestedMirror -ResiliencySettingName Mirror -MediaType SSD -NumberOfDataCopies 4 -CimSession $config.ClusterName ;

New-Volume -StoragePoolFriendlyName $config.StoragePoolName -FriendlyName Volume01 -StorageTierFriendlyNames 2WayNestedMirror -StorageTierSizes $config.CSVSize -CimSession $config.ClusterName 
 

}

function CreateCloudWitness{
    param()
    write-host -ForegroundColor Green -Object "Set Cloud Witness"

#Set Cloud Witness

Set-ClusterQuorum -Cluster $config.ClusterName -CloudWitness -AccountName $config.CloudWitnessShare  -AccessKey $Config.CloudWitnessKey

}

function SetNetIntents {
    param()
    write-host -ForegroundColor Green -Object "Setting NetworkATC Configuration"

Invoke-Command -ComputerName $ServerList -Credential $ADcred -Authentication Credssp {

#North-South Net-Intents
#New-VMSwitch -Name "HCI" -AllowManagementOS $true -EnableEmbeddedTeaming $true -MinimumBandwidthMode Weight -NetAdapterName "MGMT1", "MGMT2"
Add-NetIntent -ClusterName $using:config.ClusterName -AdapterName "MGMT1", "MGMT2"  -Name HCI -Management -Compute 
}

Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {
#Storage NetIntent
Add-NetIntent -ClusterName $using:config.ClusterName -AdapterName "SMB1", "SMB2"  -Name SMB -Storage
}

<#
start-sleep 30 

Start-ClusterResource -Cluster $config.ClusterName -Name "Cluster IP Address"

write-host -ForegroundColor Green -Object "Testing to ensure Cluster IP is online" 

$tnc_clip=Test-NetConnection $config.ClusterIP
if ($tnc_clip.pingsucceded -eq "true") {
    write-host -ForegroundColor Green -Object "Cluster in online, NetworkATC was successful"
}

elseif ($tnc_clip.pingsucceded -eq "false") {
    Start-ClusterResource -Cluster $config.ClusterName -Name Cluster IP Address
   Start-Sleep 15
}
 
 $tnc_clip2=Test-NetConnection $config.ClusterIP

if ( $tnc_clip2.pingsucceded -eq "true") {

write-host -ForegroundColor Green -Object "Cluster in online, NetworkATC was successful"
}

else {

Write-Host -ForegroundColor Red -Object "Please ensure Cluster Resources are online and Network configration is correct on nodes";

    Start-Sleep 180
}
#>
}

function registerhcicluster {
param()
write-host -ForegroundColor Green -Object "Register the Cluster to Azure Subscription"

#Register Cluster with Azure

#Register Cluster with Azure
Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {
    Connect-AzAccount -Credential $using:AADCred -TenantId $azuretenentid
    $armtoken = Get-AzAccessToken
    $graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph
    Register-AzStackHCI -SubscriptionId $using:config.AzureSubID -ComputerName $using:config.Node01 -AccountId $using:AADAccount -ArmAccessToken $armtoken.Token -GraphAccessToken $graphtoken.Token  -Region "East US" 
    }

}

function copyAKSRBInstall {
param ()

New-Item -Path \\$($config.Node01)\c$ -Name Temp -ItemType Directory

Copy-Item C:\Scripts\InstallArcRB.ps1 -Destination \\$($config.Node01)\C$\temp
}

function runAKSRBInstall{
param (
$remotevar=@{ 
                AzureSubId = $config.AzureSubID 
                AzureSPNAppID= $config.AzureSPNAppID 
                AzureSPNSecret= $config.AzureSPNSecret 
                AzureTenantID= $config.AzureTenantID 
                KeyVault= $config.KeyVault
                AKSvnetname= $config.AKSvnetname
                AKSvSwitchName =$config.AKSvSwitchName
                AKSNodeStartIP= $config.AKSNodeStartIP
                AKSNodeEndIP= $config.AKSNodeEndIP
                AKSVIPStartIP =$config.AKSVIPStartIP
                AKSVIPEndIP= $config.AKSVIPEndIP
                AKSIPPrefix =$config.AKSIPPrefix
                AKSGWIP =$config.AKSGWIP
                AKSDNSIP= $config.AKSDNSIP
                AKSImagedir =$config.AKSImagedir
                AKSWorkingdir =$config.AKSWorkingdir
                AKSCloudSvcidr =$config.AKSCloudSvcidr
                AKSResourceGroupName= $config.AKSResourceGroupName
                Location= $config.Location
                resbridgeresource_group= $config.resbridgeresource_group
                resbridgeip1= $config.resbridgeip1
                resbridgeip2= $config.resbridgeip2
                resbridgecpip= $config.resbridgecpip
                csv_path=$config.csv_path
                }
          )
    Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp -ArgumentList $remotevar -ScriptBlock {
        param (
        $RemoteVar
        )


        
                $AzureSubId = $remotevar.AzureSubID 
                $AzureSPNAppID= $remotevar.AzureSPNAppID 
                $AzureSPNSecret= $remotevar.AzureSPNSecret 
                $AzureTenantID= $remotevar.AzureTenantID 
                $KeyVault= $remotevar.KeyVault
                $AKSvnetname= $remotevar.AKSvnetname
                $AKSvSwitchName =$remotevar.AKSvSwitchName
                $AKSNodeStartIP= $remotevar.AKSNodeStartIP
                $AKSNodeEndIP= $remotevar.AKSNodeEndIP
                $AKSVIPStartIP =$remotevar.AKSVIPStartIP
                $AKSVIPEndIP= $remotevar.AKSVIPEndIP
                $AKSIPPrefix =$remotevar.AKSIPPrefix
                $AKSGWIP =$remotevar.AKSGWIP
                $AKSDNSIP= $remotevar.AKSDNSIP
                $AKSImagedir =$remotevar.AKSImagedir
                $AKSWorkingdir =$remotevar.AKSWorkingdir
                $AKSCloudSvcidr =$remotevar.AKSCloudSvcidr
                $AKSResourceGroupName= $remotevar.AKSResourceGroupName
                $Location= $remotevar.Location
                $resbridgeresource_group= $remotevar.resbridgeresource_group
                $resbridgeip1= $remotevar.resbridgeip1
                $resbridgeip2= $remotevar.resbridgeip2
                $resbridgecpip= $remotevar.resbridgecpip
                $csv_path=$RemoteVar.csv_path
        
               
        
      C:\temp\InstallArcRB.ps1 -AzureSubId $AzureSubID -AzureSPNAppID $AzureSPNAppID -AzureSPNSecret $AzureSPNSecret -AzureTenantID $AzureTenantID -KeyVault $KeyVault -AKSvnetname $AKSvnetname -AKSvSwitchName $AKSvSwitchName -AKSNodeStartIP $AKSNodeStartIP -AKSNodeEndIP $AKSNodeEndIP -AKSVIPStartIP $AKSVIPStartIP -AKSVIPEndIP $AKSVIPEndIP -AKSIPPrefix $AKSIPPrefix -AKSGWIP $AKSGWIP -AKSDNSIP $AKSDNSIP -AKSImagedir $AKSImagedir -AKSWorkingdir $AKSWorkingdir -AKSCloudSvcidr $AKSCloudSvcidr -AKSResourceGroupName $AKSResourceGroupName -Location $Location -resbridgecpip $resbridgecpip -resbridgeresource_group $resbridgeresource_group -resbridgeip1 $resbridgeip1 -resbridgeip2 $resbridgeip2 -csv_path $csv_path
  

             }

    }

    function addcustomlocation{
    param($remotevar=@{
                AzureSPNAppID= $config.AzureSPNAppID 
                AzureSPNSecret= $config.AzureSPNSecret 
                AzureTenantID= $config.AzureTenantID  
                resource_group=$config.resbridgeresource_group
                subscription=$config.AzureSubID
                Location=$config.Location
                customloc_name=$config.customloc_name
                vSwitchName=$config.AKSvSwitchName
                csv_path=$config.csv_path
                akshybrid_virtualnetwork=$config.akshybrid_virtualnetwork
                akshybrid_ipaddressprefix=$config.akshybrid_ipaddressprefix
                akshybrid_gateway=$config.akshybrid_gateway
                akshybrid_dns=$config.akshybrid_dns
                akshybrid_vippoolstart=$config.akshybrid_vippoolstart
                akshybrid_vippoolend=$config.akshybrid_vippoolstart
                akshybrid_k8snodeippoolstart=$config.akshybrid_k8snodeippoolstart
                akshybrid_k8snodeippoolend=$config.akshybrid_k8snodeippoolstart
                vmss_vnetname=$config.vmss_vnetname
                }
        )

    Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp -ArgumentList $remotevar -ScriptBlock {

         param (
        $RemoteVar
        )
        

                $AzureSPNAppID= $remotevar.AzureSPNAppID 
                $AzureSPNSecret= $remotevar.AzureSPNSecret 
                $AzureTenantID= $remotevar.AzureTenantID
                $resource_group=$remotevar.resource_group
                $subscription=$remotevar.subscription
                $Location=$remotevar.Location
                $customlocname=$remotevar.customloc_name
                $vSwitchName=$RemoteVar.vSwitchName
                $csv_path=$remotevar.csv_path
                $vmss_vnetname=$remotevar.vmss_vnetname
                $akshybrid_virtualnetwork=$remotevar.akshybrid_virtualnetwork
                $akshybrid_ipaddressprefix=$remotevar.akshybrid_ipaddressprefix
                $akshybrid_gateway=$remotevar.akshybrid_gateway
                $akshybrid_dns=$remotevar.akshybrid_dns
                $akshybrid_vippoolstart=$remotevar.akshybrid_vippoolstart
                $akshybrid_vippoolend=$remotevar.akshybrid_vippoolend
                $akshybrid_k8snodeippoolstart=$remotevar.akshybrid_k8snodeippoolstart
                $akshybrid_k8snodeippoolend=$remotevar.akshybrid_k8snodeippoolend

        Write-Host "Logging into Azure" -ForegroundColor Green -BackgroundColor Black

        az login --use-device-code --tenant $azuretenantid
        az config set extension.use_dynamic_install=yes_without_prompt

        Install-Module -Name ArcHci -RequiredVersion 0.2.18

        $hciClusterId= (Get-AzureStackHci).AzureResourceUri
        $resource_name= ((Get-AzureStackHci).AzureResourceName) + "-arcbridge"
       

      #Create VM Operator Extension
      az k8s-extension create --cluster-type appliances --cluster-name $resource_name --resource-group $resource_group --name hci-vmoperator --extension-type Microsoft.AZStackHCI.Operator --scope cluster --release-namespace helm-operator2 --configuration-settings Microsoft.CustomLocation.ServiceAccount=hci-vmoperator --config-protected-file $csv_path\ResourceBridge\hci-config.json --configuration-settings HCIClusterID=$hciClusterId --auto-upgrade true

      #Create AKS-Hybrid Extension
      az k8s-extension create -g $resource_group -c $resource_name --cluster-type appliances --name hci-aksoperator --extension-type Microsoft.HybridAKSOperator --config Microsoft.CustomLocation.ServiceAccount=hci-vmoperator --version "0.1.101-onebranch-official" --release-train "staging" 
   
      #Get Applicance Extension Detail
      $applianceID=(az arcappliance show -g $resource_group  -n $resource_name --query id -o tsv)
       
      $operatorname = "hci-vmoperator"
      
      #VM Operator Extension ID
      $extensionID=(az k8s-extension show -g $resource_group  -c $resource_name --cluster-type appliances --name $operatorname --query id -o tsv)
      
      #AKS Hybrid Extension ID
      $ClusterExtensionResourceId=az k8s-extension show -g $resource_group -c $resource_name --cluster-type appliances --name hci-aksoperator --query id -o tsv


      #Create Custom Location with VM Operator
      az customlocation create --resource-group $resource_group --name $CustomLocName --cluster-extension-ids $extensionID --namespace $operatorname --host-resource-id $applianceID
       
      #Update Custom Location with AKS-Hybrid Extension
      az customlocation patch -g $resource_group -n $CustomLocName --namespace $operatorname  --host-resource-id $applianceID --cluster-extension-ids $ClusterExtensionResourceId $extensionID                  


      #VM-Operator- VNet Creation Repeat this step for every new Vnet used by VM Operator
      
      Write-Host "Creating Virtual Network Resource for Arc Virtual Machine Management" -ForegroundColor Green -BackgroundColor Black

      #$vlanid="0"   

      $vnetName=$vmss_vnetname

      New-MocGroup -name "Default_Group" -location "MocLocation"
        
      New-MocVirtualNetwork -name "$vnetName" -group "Default_Group" -tags @{'VSwitch-Name' = "$vSwitchName"}  

      az azurestackhci virtualnetwork create --subscription $subscription --resource-group $resource_group --extended-location name="/subscriptions/$subscription/resourceGroups/$resource_group/providers/Microsoft.ExtendedLocation/customLocations/$customlocname" type="CustomLocation" --location $Location --network-type "Transparent" --name $vnetName #--vlan $vlanid

      #VM-Operator-Marketplace Image Download
       
      $osType = "Windows"

      $customLocationID=(az customlocation show --resource-group $resource_group --name "$customlocname" --query id -o tsv)

      az azurestackhci image create --subscription $subscription --resource-group $resource_group --extended-location name=$customLocationID type="CustomLocation" --location $Location --name "Server22AECore"  --os-type $osType --offer "windowsserver" --publisher "microsoftwindowsserver" --sku "2022-datacenter-azure-edition-core" --version "20348.707.220609"

      #AKS-Hybrid Create AKS Virtual Network
   

      New-KvaVirtualNetwork -name $akshybrid_virtualnetwork -vswitchname "$vSwitchName" -ipaddressprefix $akshybrid_ipaddressprefix  -gateway $akshybrid_gateway -dnsservers $akshybrid_dns -vippoolstart $akshybrid_vippoolstart -vippoolend $akshybrid_vippoolend -k8snodeippoolstart $akshybrid_k8snodeippoolstart -k8snodeippoolend $akshybrid_k8snodeippoolend -kubeconfig $csv_path\ResourceBridge\config\ 
      
      az hybridaks vnet create --name $akshybrid_virtualnetwork --resource-group $resource_group --custom-location $customlocname --moc-vnet-name $akshybrid_virtualnetwork
      
      #AKS-Hybrid Download Mariner Images
      Add-ArcHciK8sGalleryImage -k8sVersion 1.22.11

    }

}




#End Function Region

#Begin Main Region

<#---------------------------------------------------------------------------------------------------------------#>


$config=LoadVariables
$ServerList = $config.Node01, $config.Node02

$azlogin = Connect-AzAccount -Subscription $config.azuresubid 
Select-AzSubscription -Subscription $config.AzureSubID
#Set AD Domain Cred
$AzDJoin = Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "djoin"
$ADcred = [pscredential]::new("fc\djoin",$AZDJoin.SecretValue)
#$ADpassword = ConvertTo-SecureString "" -AsPlainText -Force
#$ADCred = New-Object System.Management.Automation.PSCredential ("contoso\djoiner", $ADpassword)

#Set Cred for AAD tenant and subscription
$AADAccount = "azstackadmin@azurestackdemo1.onmicrosoft.com"
$AADAdmin=Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "azurestackadmin"
$AADCred = [pscredential]::new("azstackadmin@azurestackdemo1.onmicrosoft.com",$AADAdmin.SecretValue)
$Arcsecretact=Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "FCSPN"
$ARCSecret=$arcsecretact.SecretValue
$Session1=New-PSSession -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp

ConfigureWorkstation
ConfigureNodes
ConfigureNode01
ConfigureNode02
PrepareStorage
CreateCluster
SetLiveMigration
DeployS2D
EnableCAU
ConfirmFunctionLevels
CreateCSV
CreateCloudWitness
SetNetintents

registerhcicluster
copyAKSRBInstall
runAKSRBInstall

addcustomlocation




    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    $orginalErrorAction = $ErrorActionPreference
            $ErrorActionPreference = "Inquire"
            
            $logFile = ('.\ExecutionTranscript.log')
            Start-Transcript -Path $logFile -Append
            
            try 
            {
                Initialize-Variables
                $progressLog = Get-Content -Path '.\progress.log'
            
                $currentStepName = 'Init'
                $currentStepIndex = 0
            
                do 
                {
                    if ($progressLog[$currentStepIndex].Contains("Pending"))
                    {
                        $currentStepName = ($progressLog[$currentStepIndex].Split())[0]
                        Invoke-Expression -Command $currentStepName
                    }
                    $currentStepIndex++
                    $progressLog = Get-Content -Path '.\progress.log' -Force
                }
                until ( $progressLog[$currentStepIndex] -eq "Done" )
            
            }
            finally 
            {
                Stop-Transcript
                $ErrorActionPreference = $orginalErrorAction
            }





























# Main execution begins here







write-host -ForegroundColor Green -Object "Cluster is Deployed; Enjoy!"

#Appendix

