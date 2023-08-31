param(
    [Parameter(Mandatory)]
    [String] $ConfigurationDataFile
) 

$WelcomeMessage="Welcome to the Azure Stack HCI 2 Node Deployment script, this script will deploy out a fully functional 2 Node Azure Stack HCI Cluster, in a Switchless configuraiton. The first step in this deployment is to ask for you to sign into your Azure Subscription."
#Begin Function Region

       
function LoadVariables {
   
    #Set Variables from Config File

$config=Import-PowerShellDataFile -Path $ConfigurationDataFile 
Write-Host -ForegroundColor Green -Object $WelcomeMessage
return $config 
}

function RetrieveCredentials{
param ()
$adcred=Get-Credential -Message "Please enter the credentials for the domain joiner account"

# Service Principal Credentials Conversion (Please replace with Azure Key Vault Stored Secrets)
$spn_secure_password = ConvertTo-SecureString $config.AzureSPNSecret -AsPlainText -Force  
$spnCred = New-Object System.Management.Automation.PSCredential ($config.AzureSPNAppID, $spn_secure_password)



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
    Install-WindowsFeature -Name "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-Powershell","FS-Data-Deduplication", "Storage-Replica", "NetworkATC", "System-Insights", "NetworkHUD" -IncludeAllSubFeature -IncludeManagementTools
    Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name Az.StackHCI -Force -All
    Install-Module -Name test-netstack -Force -All
    Install-Module -Name Az.StackHCI.NetworkHUD -Force
    Enable-WSManCredSSP -Role Server -Force
    New-NetFirewallRule -DisplayName “ICMPv4” -Direction Inbound -Action Allow -Protocol icmpv4 -Enabled True
    Enable-NetFirewallRule -DisplayGroup “Remote Desktop”
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0
    Set-TimeZone -Name "Eastern Standard Time" 
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
    $m1=Get-NetAdapter -Name "Lom1 Port1"
    $m2=Get-NetAdapter -Name "Lom1 Port2"
    $m1 | Rename-NetAdapter -NewName "MGMT"
    $m2 | Rename-NetAdapter -NewName "SMB"
    
    
    #MGMT
    New-NetIPAddress -InterfaceAlias "MGMT" -IPAddress $using:config.node01_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP  | Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    
    #Storage 
    Get-NetAdapter -Name "Ethernet *"| Disable-NetAdapter -Confirm:$false
}
}

function ConfigureNode02 {
    param ()
    Write-Host -ForegroundColor Green -Object "Configure Node02"

Invoke-Command -ComputerName $config.Node02 -Credential $ADCred -ScriptBlock {
    # Configure IP and subnet mask, no default gateway for Storage interfaces
   
    #Rename Net Adapters
    $m1=Get-NetAdapter -Name "Lom1 Port1"
    $m2=Get-NetAdapter -Name "Lom1 Port2"
    $m1 | Rename-NetAdapter -NewName "MGMT"
    $m2 | Rename-NetAdapter -NewName "SMB"
    
    
    #MGMT
    New-NetIPAddress -InterfaceAlias "MGMT" -IPAddress $using:config.node01_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP  | Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    
    #Storage 
    Get-NetAdapter -Name "Ethernet *"| Disable-NetAdapter -Confirm:$false
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

}

}


function DeployS2D {
    param ()
    Write-Host -ForegroundColor Green -Object "Enable Storage Spaces Direct"

#Enable S2D
Invoke-Command -ComputerName $config.node01 -Credential $adcred -Authentication Credssp -ScriptBlock {
    Enable-ClusterStorageSpacesDirect -PoolFriendlyName $using:config.StoragePoolName -Confirm:0 
}
    }

function EnableCAU {
param()
#############Enable CAU and update to latest 21H2 bits...###############
Invoke-Command -ComputerName $config.node01 -Credential $adcred -Authentication Credssp -ScriptBlock {
   
    #Now we can add the CAU role...
    Add-CauClusterRole -ClusterName $using:config.ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName "$using:config.ClusterName"+"-CAU"  -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2020 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose

    #Enable KSR on ALl and Future CAU 
    Get-Cluster -Name $using:config.ClusterName | Set-ClusterParameter -Name CauEnableSoftReboot -Value 1 -Create

    #Now we can force an update...
    Invoke-CauRun -ClusterName $using:config.ClusterName -CauPluginName "Microsoft.WindowsUpdatePlugin" -MaxFailedNodes 1 -MaxRetriesPerNode 3 -RequireAllNodesOnline -Force
}

    }

function CreateCSV {
    param ()
    write-host -ForegroundColor Green -Object "Creating Cluster Shared Volume"

#Create S2D Tier and Volumes
Invoke-Command -ComputerName $config.node01 -Credential $adcred -Authentication Credssp -ScriptBlock {
    New-Volume -StoragePoolFriendlyName $using:config.StoragePoolName -FriendlyName $using:config.CSVFriendlyname -Size $using:config.CSVSize 
} 

    }

function CreateCloudWitness{
    param()
    write-host -ForegroundColor Green -Object "Set Cloud Witness"

#Set Cloud Witness
Invoke-Command -ComputerName $config.node01 -Credential $adcred -Authentication Credssp -ScriptBlock {
    Set-ClusterQuorum -Cluster $using:config.ClusterName -CloudWitness -AccountName $using:config.CloudWitnessShare  -AccessKey $using:Config.CloudWitnessKey
}
    }

function SetNetIntents {
    param()
    write-host -ForegroundColor Green -Object "Setting NetworkATC Configuration"

Invoke-Command -ComputerName $config.node01 -Credential $ADcred -Authentication Credssp {

#Network Intents
#New-VMSwitch -Name "HCI" -AllowManagementOS $true -EnableEmbeddedTeaming $true -MinimumBandwidthMode Weight -NetAdapterName "MGMT1", "MGMT2"
#North-South Intent
Add-NetIntent -ClusterName $using:config.ClusterName -AdapterName "MGMT"  -Name HCIVS -Management -Compute 

#Storage Intent
#$smb=New-NetIntentGlobalClusterOverrides
#$smb.VirtualMachineMigrationPerformanceOption="SMB"
#$smb.EnableVirtualMachineMigrationPerformanceSelection=$false
Add-NetIntent -Name "SMB" -AdapterName "SMB" -Storage 
#-GlobalClusterOverrides $smb
}
}

function spncreds {
    param (
        [Parameter(Required)]
        [Boolean] $CreateSPN,
        [Parameter(Optional)]
        [String] $SPNAppID,
        [Parameter(Optional)]
        [String] $SPNAppSecret,
        [Parameter(Optional)]
        [String] $KeyVaultName,
        [Parameter(Optional)]
        [String] $KeyVaultSecretName
    )
    if ($CreateSPN -eq "False")
    {
        #Create a new application registration
    $app = New-AzADApplication -DisplayName "<unique_name>"

    #Create a new SPN corresponding to the application registration
    $sp = New-AzADServicePrincipal -ApplicationId  $app.AppId -Role "Reader" 

    #Roles required on SPN for Arc onboarding
    $AzureConnectedMachineOnboardingRole = "Azure Connected Machine Onboarding"
    $AzureConnectedMachineResourceAdministratorRole = "Azure Connected Machine Resource Administrator"

    #Assign roles to the created SPN
    New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName $AzureConnectedMachineOnboardingRole | Out-Null
    New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName $AzureConnectedMachineResourceAdministratorRole | Out-Null

    # Set password validity time. SPN must be updated on the HCI cluster after this timeframe.
    $pwdExpiryInYears = 300
    $start = Get-Date
    $end = $start.AddYears($pwdExpiryInYears)
    $pw = New-AzADSpCredential -ObjectId $sp.Id -StartDate $start -EndDate $end
    $password = ConvertTo-SecureString $pw.SecretText -AsPlainText -Force  

    # Create SPN credentials object to be used in the register-azstackhci cmdlet
    $spnCred = New-Object System.Management.Automation.PSCredential ($app.AppId, $password)

    }
    
}

function registerhcicluster {
param()
$clstate=monitorclusterstate
if ($clstate="Online") {
    write-host -ForegroundColor Green -Object "Register the Cluster to Azure Subscription"

#Register Cluster with Azure
Write-Host "Starting Cluster Registration Process with Azure utilizing User Creds via Login Code" -ForegroundColor Green -BackgroundColor Black
Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {
    Install-Module Az.Resources -Force -MinimumVersion "2.6.0"
    Install-Module Az.StackHCI -Force -MinimumVersion "2.0.0"
    Register-AzStackHCI -SubscriptionId $using:config.AzureSubID -ComputerName $using:config.Node01   -Region "East US" -UseDeviceAuthentication -ResourceName $using:config.ClusterName -ResourceGroupName $using:config.ClusterName
    #With SPN 
    #Register-AzStackHCI -SubscriptionId $using:AzureSubID -Region $using:location -ArcSpnCredential:$using:spnCred    
}
}
else {
     monitorclusterstate
}



}

function RegisterHCIClusterwithSPN {
    param ()
    $clstate=monitorclusterstate
    if ($clstate="Online") {
        write-host -ForegroundColor Green -Object "Register the Cluster to Azure Subscription"
    
    #Register Cluster with Azure
    Write-Host "Retrieving SPN Credentials from Config File. Please change this to an Azure Key Vault in the Future" -ForegroundColor Green -BackgroundColor Black
    RetrieveCredentials
    Write-Host "Starting Cluster Registration Process with Azure utilizing SPN" -ForegroundColor Green -BackgroundColor Black
    Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {
        Install-Module Az.Resources -Force -MinimumVersion "2.6.0"
        Install-Module Az.StackHCI -Force -MinimumVersion "2.0.0"
        #Without SPN
        #Register-AzStackHCI -SubscriptionId $using:config.AzureSubID -ComputerName $using:config.Node01   -Region $using:config.location  -UseDeviceAuthentication -ResourceName $using:config.ClusterName -ResourceGroupName $using:config.ClusterName 
        #With SPN
        Register-AzStackHCI -SubscriptionId $using:config.AzureSubID -ComputerName $using:config.Node01   -Region $using:config.location  -ResourceName $using:config.ClusterName -ResourceGroupName $using:config.ClusterName -ArcSpnCredential:$using:spnCred
    }
    }
    else {
         monitorclusterstate
    }



}

function enableHybridUseBenefit {
    param()
        Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {
        Invoke-AzStackHciExtendClusterSoftwareAssuranceBenefit -ClusterName $using:config.ClusterName -ResourceGroupName $using:config.ClusterName -SoftwareAssuranceIntent "Enable"
    }
}


function copyAKSRBInstall {
param ()

New-Item -Path \\$($config.Node01)\c$ -Name Temp -ItemType Directory

Copy-Item .\Infra-Team\Deployment\InstallArcRB.ps1 -Destination \\$($config.Node01)\C$\temp
}

function copyMOCRBInstall {
    param ()
    
    New-Item -Path \\$($config.Node01)\c$ -Name Temp -ItemType Directory
    
    Copy-Item .\Infra-Team\Deployment\InstallMocRB.ps1 -Destination \\$($config.Node01)\C$\temp
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
                AKSvSwitchName = $config.AKSvSwitchName
                AKSNodeStartIP= $config.AKSNodeStartIP
                AKSNodeEndIP= $config.AKSNodeEndIP
                AKSVIPStartIP = $config.AKSVIPStartIP
                AKSVIPEndIP= $config.AKSVIPEndIP
                AKSIPPrefix = $config.AKSIPPrefix
                AKSGWIP = $config.AKSGWIP
                AKSDNSIP= $config.AKSDNSIP
                AKSImagedir = $config.AKSImagedir
                AKSWorkingdir = $config.AKSWorkingdir
                AKSCloudSvcidr = $config.AKSCloudSvcidr
                AKSClusterRoleName = $config.AKSClusterRoleName
                AKSResourceGroupName= $config.AKSResourceGroupName
                AKSVlan = $config.AKSVlan
                Location= $config.Location
                resbridgeresource_group= $config.resbridgeresource_group
                resbridgeip1= $config.resbridgeip1
                resbridgeip2= $config.resbridgeip2
                resbridgecpip= $config.resbridgecpip
                csv_path= $config.csv_path
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
                $AKSvSwitchName = $remotevar.AKSvSwitchName
                $AKSNodeStartIP= $remotevar.AKSNodeStartIP
                $AKSNodeEndIP= $remotevar.AKSNodeEndIP
                $AKSVIPStartIP = $remotevar.AKSVIPStartIP
                $AKSVIPEndIP= $remotevar.AKSVIPEndIP
                $AKSIPPrefix = $remotevar.AKSIPPrefix
                $AKSGWIP = $remotevar.AKSGWIP
                $AKSDNSIP= $remotevar.AKSDNSIP
                $AKSImagedir = $remotevar.AKSImagedir
                $AKSWorkingdir = $remotevar.AKSWorkingdir
                $AKSCloudSvcidr = $remotevar.AKSCloudSvcidr
                $AKSClusterRoleName = $RemoteVar.AKSClusterRoleName
                $AKSResourceGroupName= $remotevar.AKSResourceGroupName
                $AKSVlan = $RemoteVar.AKSVlan
                $Location= $remotevar.Location
                $resbridgeresource_group= $remotevar.resbridgeresource_group
                $resbridgeip1= $remotevar.resbridgeip1
                $resbridgeip2= $remotevar.resbridgeip2
                $resbridgecpip= $remotevar.resbridgecpip
                $csv_path= $RemoteVar.csv_path
        
               
        
                C:\temp\InstallArcRB.ps1 -AzureSubId $AzureSubID -AzureSPNAppID $AzureSPNAppID -AzureSPNSecret $AzureSPNSecret -AzureTenantID $AzureTenantID -KeyVault $KeyVault -AKSvnetname $AKSvnetname -AKSvSwitchName $AKSvSwitchName -AKSNodeStartIP $AKSNodeStartIP -AKSNodeEndIP $AKSNodeEndIP -AKSVIPStartIP $AKSVIPStartIP -AKSVIPEndIP $AKSVIPEndIP -AKSIPPrefix $AKSIPPrefix -AKSGWIP $AKSGWIP -AKSDNSIP $AKSDNSIP -AKSImagedir $AKSImagedir -AKSWorkingdir $AKSWorkingdir -AKSCloudSvcidr $AKSCloudSvcidr -aksClusterRoleName $AKSClusterRoleName -AKSResourceGroupName $AKSResourceGroupName -Location $Location -resbridgecpip $resbridgecpip -resbridgeresource_group $resbridgeresource_group -resbridgeip1 $resbridgeip1 -resbridgeip2 $resbridgeip2 -csv_path $csv_path -aksvlan $AKSVlan
  

             }

    }

    function runMocRBInstall{
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
                        #AKSIPPrefix=$config.akshybrid_ipaddressprefix
                        #AKSGWIP =$config.akshybrid_gateway
                        AKSDNSIP= $config.akshybrid_dns
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
                        resbridge_ipaddressprefix=$config.resbridge_ipaddressprefix
                        resbridgevlanid=$config.resbridge_vlanid
                        resbridge_gateway=$config.resbridge_gateway
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
                        #$AKSIPPrefix =$remotevar.AKSIPPrefix
                        #$AKSGWIP =$remotevar.AKSGWIP
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
                        $resbridge_ipaddressprefix=$RemoteVar.resbridge_ipaddressprefix
                        $resbridgevlanid=$RemoteVar.resbridgevlanid
                        $resbridge_gateway=$RemoteVar.resbridge_gateway
                
                       
                
              C:\temp\InstallMocRB.ps1 -AzureSubId $AzureSubID -AzureSPNAppID $AzureSPNAppID -AzureSPNSecret $AzureSPNSecret -AzureTenantID $AzureTenantID -KeyVault $KeyVault -AKSvnetname $AKSvnetname -AKSvSwitchName $AKSvSwitchName -AKSNodeStartIP $AKSNodeStartIP -AKSNodeEndIP $AKSNodeEndIP -AKSVIPStartIP $AKSVIPStartIP -AKSVIPEndIP $AKSVIPEndIP -resbridge_ipaddressprefix $resbridge_ipaddressprefix -resbridge_gateway $resbridge_gateway -AKSDNSIP $AKSDNSIP -AKSImagedir $AKSImagedir -AKSWorkingdir $AKSWorkingdir -AKSCloudSvcidr $AKSCloudSvcidr -AKSResourceGroupName $AKSResourceGroupName -Location $Location -resbridgecpip $resbridgecpip -resbridgeresource_group $resbridgeresource_group -resbridgeip1 $resbridgeip1 -resbridgeip2 $resbridgeip2 -csv_path $csv_path -resbridgevlanid $resbridgevlanid
          
        
                     }
        
            }
        
    function addcustomlocation_ConnectedK8s{
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
                akshybrid_vippoolend=$config.akshybrid_vippoolend
                akshybrid_k8snodeippoolstart=$config.akshybrid_k8snodeippoolstart
                akshybrid_k8snodeippoolend=$config.akshybrid_k8snodeippoolend
                vmss_vnetname=$config.vmss_vnetname
                akshybridvlan                   =$config.akshybridvlan
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
                $akshybridvlanid=$remotevar.akshybridvlanid

        Write-Host "Logging into Azure" -ForegroundColor Green -BackgroundColor Black

        az login --use-device-code --tenant $azuretenantid
        az account set --subscription $subscription
        az config set extension.use_dynamic_install=yes_without_prompt

        Install-Module -Name ArcHci -Repository PSGallery -AcceptLicense -Force -RequiredVersion 0.2.24

        $hciClusterId= (Get-AzureStackHci).AzureResourceUri
        $resource_name= ((Get-AzureStackHci).AzureResourceName) + "-arcbridge"
        $operatorname = "hci-vmoperator"
        $aksoperatorname ="hci-aksoperators"

      #Create VM Operator Extension
      az k8s-extension create --cluster-type appliances --cluster-name $resource_name --resource-group $resource_group --name $operatorname --extension-type Microsoft.AZStackHCI.Operator --scope cluster --release-namespace helm-operator2 --configuration-settings Microsoft.CustomLocation.ServiceAccount=hci-vmoperator --config-protected-file $csv_path\ResourceBridge\hci-config.json --configuration-settings HCIClusterID=$hciClusterId --auto-upgrade true
      
      #Create AKS-Hybrid Extension
      az k8s-extension create -g $resource_Group  -c $resource_name --cluster-type appliances --name $aksoperatorname --extension-type Microsoft.HybridAKSOperator --config Microsoft.CustomLocation.ServiceAccount="default"
      
      #Get Applicance Extension Detail
      $applianceID=(az arcappliance show -g $resource_group  -n $resource_name --query id -o tsv)
      
      #VM Operator Extension ID
      $extensionID=(az k8s-extension show -g $resource_group  -c $resource_name --cluster-type appliances --name $operatorname --query id -o tsv)
      
      #AKS Hybrid Extension ID
      #$ClusterExtensionResourceId=az k8s-extension show -g $resource_group -c $resource_name --cluster-type appliances --name $aksoperatorname --query id -o tsv


      #Create Custom Location with VM Operator
      az customlocation create --resource-group $resource_group --name $CustomLocName --cluster-extension-ids $extensionID --namespace $operatorname --host-resource-id $applianceID
       
      #Update Custom Location with AKS-Hybrid Extension
      #az customlocation patch -g $resource_group -n $CustomLocName --namespace $operatorname  --host-resource-id $applianceID --cluster-extension-ids $ClusterExtensionResourceId $extensionID                  


      #VM-Operator- VNet Creation Repeat this step for every new Vnet used by VM Operator
      
      Write-Host "Creating Virtual Network Resource for Arc Virtual Machine Management" -ForegroundColor Green -BackgroundColor Black

      #$vlanid="0"   

      $vnetName=$vmss_vnetname

      New-MocGroup -name "Default_Group" -location "MocLocation" -ErrorAction ignore 
        
      New-MocVirtualNetwork -name "$vnetName" -group "Default_Group" -tags @{'VSwitch-Name' = "$vSwitchName"}  

      az azurestackhci virtualnetwork create --subscription $subscription --resource-group $resource_group --extended-location name="/subscriptions/$subscription/resourceGroups/$resource_group/providers/Microsoft.ExtendedLocation/customLocations/$customlocname" type="CustomLocation" --location $Location --network-type "Transparent" --name $vnetName #--vlan $vlanid

      #VM-Operator-Marketplace Image Download
       
      $osType = "Windows"

      $customLocationID=(az customlocation show --resource-group $resource_group --name "$customlocname" --query id -o tsv)

      az azurestackhci image create --subscription $subscription --resource-group $resource_group --extended-location name=$customLocationID type="CustomLocation" --location $Location --name "Server22AECore"  --os-type $osType --offer "windowsserver" --publisher "microsoftwindowsserver" --sku "2022-datacenter-azure-edition-core" --version "20348.707.220609"

      #AKS-Hybrid Create AKS Virtual Network
      #New-ArcHciVirtualNetwork -name $akshybrid_virtualnetwork -vswitchName "$vSwitchName" -ipaddressprefix $akshybrid_ipaddressprefix -gateway $akshybrid_gateway -dnsservers $akshybrid_dns -vippoolstart $akshybrid_vippoolstart -vippoolend $akshybrid_vippoolend -k8snodeippoolstart $akshybrid_k8snodeippoolstart -k8snodeippoolend $akshybrid_k8snodeippoolend -vlanid $akshybridvlanid
      #az hybridaks vnet create --name $akshybrid_virtualnetwork --resource-group $resource_group --custom-location $customlocname --moc-vnet-name $akshybrid_virtualnetwork
      
      #AKS-Hybrid Download Mariner Images
      #Add-ArcHciK8sGalleryImage -k8sVersion 1.22.11 -version 1.0.16.10113

    }

}

function addcustomlocation_ProvisonedK8s{
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
                akshybrid_vippoolend=$config.akshybrid_vippoolend
                akshybrid_k8snodeippoolstart=$config.akshybrid_k8snodeippoolstart
                akshybrid_k8snodeippoolend=$config.akshybrid_k8snodeippoolend
                vmss_vnetname=$config.vmss_vnetname
                akshybridvlan                   =$config.akshybridvlan
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
                $akshybridvlanid=$remotevar.akshybridvlanid

        Write-Host "Logging into Azure" -ForegroundColor Green -BackgroundColor Black

        az login --use-device-code --tenant $azuretenantid
        az account set --subscription $subscription
        az config set extension.use_dynamic_install=yes_without_prompt

        Install-Module -Name ArcHci -Repository PSGallery -AcceptLicense -Force -RequiredVersion 0.2.24

        $hciClusterId= (Get-AzureStackHci).AzureResourceUri
        $resource_name= ((Get-AzureStackHci).AzureResourceName) + "-arcbridge"
        $operatorname = "hci-vmoperator"
        $aksoperatorname ="hci-aksoperators"

      #Create VM Operator Extension
      az k8s-extension create --cluster-type appliances --cluster-name $resource_name --resource-group $resource_group --name $operatorname --extension-type Microsoft.AZStackHCI.Operator --scope cluster --release-namespace helm-operator2 --configuration-settings Microsoft.CustomLocation.ServiceAccount=hci-vmoperator --config-protected-file $csv_path\ResourceBridge\hci-config.json --configuration-settings HCIClusterID=$hciClusterId --auto-upgrade true
      
      #Create AKS-Hybrid Extension
      az k8s-extension create -g $resource_Group  -c $resource_name --cluster-type appliances --name $aksoperatorname --extension-type Microsoft.HybridAKSOperator --config Microsoft.CustomLocation.ServiceAccount="default"
      
      #Get Applicance Extension Detail
      $applianceID=(az arcappliance show -g $resource_group  -n $resource_name --query id -o tsv)
      
      #VM Operator Extension ID
      $extensionID=(az k8s-extension show -g $resource_group  -c $resource_name --cluster-type appliances --name $operatorname --query id -o tsv)
      
      #AKS Hybrid Extension ID
      $ClusterExtensionResourceId=az k8s-extension show -g $resource_group -c $resource_name --cluster-type appliances --name $aksoperatorname --query id -o tsv


      #Create Custom Location with VM Operator
      az customlocation create --resource-group $resource_group --name $CustomLocName --cluster-extension-ids $extensionID --namespace $operatorname --host-resource-id $applianceID
       
      #Update Custom Location with AKS-Hybrid Extension
      az customlocation patch -g $resource_group -n $CustomLocName --namespace $operatorname  --host-resource-id $applianceID --cluster-extension-ids $ClusterExtensionResourceId $extensionID                  


      #VM-Operator- VNet Creation Repeat this step for every new Vnet used by VM Operator
      
      Write-Host "Creating Virtual Network Resource for Arc Virtual Machine Management" -ForegroundColor Green -BackgroundColor Black

      #$vlanid="0"   

      $vnetName=$vmss_vnetname

      New-MocGroup -name "Default_Group" -location "MocLocation" -ErrorAction ignore 
        
      New-MocVirtualNetwork -name "$vnetName" -group "Default_Group" -tags @{'VSwitch-Name' = "$vSwitchName"}  

      az azurestackhci virtualnetwork create --subscription $subscription --resource-group $resource_group --extended-location name="/subscriptions/$subscription/resourceGroups/$resource_group/providers/Microsoft.ExtendedLocation/customLocations/$customlocname" type="CustomLocation" --location $Location --network-type "Transparent" --name $vnetName #--vlan $vlanid

      #VM-Operator-Marketplace Image Download
       
      $osType = "Windows"

      $customLocationID=(az customlocation show --resource-group $resource_group --name "$customlocname" --query id -o tsv)

      az azurestackhci image create --subscription $subscription --resource-group $resource_group --extended-location name=$customLocationID type="CustomLocation" --location $Location --name "Server22AECore"  --os-type $osType --offer "windowsserver" --publisher "microsoftwindowsserver" --sku "2022-datacenter-azure-edition-core" --version "20348.707.220609"

      #AKS-Hybrid Create AKS Virtual Network
      New-ArcHciVirtualNetwork -name $akshybrid_virtualnetwork -vswitchName "$vSwitchName" -ipaddressprefix $akshybrid_ipaddressprefix -gateway $akshybrid_gateway -dnsservers $akshybrid_dns -vippoolstart $akshybrid_vippoolstart -vippoolend $akshybrid_vippoolend -k8snodeippoolstart $akshybrid_k8snodeippoolstart -k8snodeippoolend $akshybrid_k8snodeippoolend -vlanid $akshybridvlanid
      az hybridaks vnet create --name $akshybrid_virtualnetwork --resource-group $resource_group --custom-location $customlocname --moc-vnet-name $akshybrid_virtualnetwork
      
      #AKS-Hybrid Download Mariner Images
      Add-ArcHciK8sGalleryImage -k8sVersion 1.22.11 -version 1.0.16.10113

    }

}
function removecustomlocation{
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
        az account set --subscription $subscription
        az config set extension.use_dynamic_install=yes_without_prompt

        Install-Module -Name ArcHci -Repository PSGallery -AcceptLicense -Force -RequiredVersion 0.2.24

        $hciClusterId= (Get-AzureStackHci).AzureResourceUri
        $resource_name= ((Get-AzureStackHci).AzureResourceName) + "-arcbridge"
        $operatorname = "hci-vmoperator"
        $aksoperatorname ="hci-aksoperators"

      #Delete AKS Hybrid Network
      Write-Host "Deleting AKS-Hybrid Network" -ForegroundColor Green -BackgroundColor Black
      az hybridaks vnet delete --resource-group $resource_group --name $akshybrid_virtualnetwork --yes
      $aks_mocvnet=get-mocvirtualnetwork -group "target-group"
      if ($aks_mocvnet -ne $null) {
        Remove-MocVirtualNetwork -group "target-group" -name $akshybrid_virtualnetwork -ErrorAction Continue -WarningAction Ignore
      
      }
      else {
        Write-Host "Moc Virtual Network is already removed, moving on" -ForegroundColor Green -BackgroundColor Black
      }
      
      
      #Delete AKS Images
    #  Remove-ArcHciK8sGalleryImage -k8sVersion 1.22.11 -version 1.0.16.10113

      #Delete VM Operator Virtual Network
      Write-Host "Deleting VM Network" -ForegroundColor Green -BackgroundColor Black
      az azurestackhci virtualnetwork delete --subscription $subscription --resource-group $resource_group --name $vmss_vnetname --yes
      
      $vm_mocvnet=get-mocvirtualnetwork -group "Default_Group"
      if ($vm_mocvnet -ne $null) {
        Remove-MocVirtualNetwork -name $vmss_vnetname -group "Default_Group" -ErrorAction Continue -WarningAction Ignore
      }
      else {
        Write-Host "VM Virtual Network is already removed, moving on" -ForegroundColor Green -BackgroundColor Black
      }
      

      #Delete VM Gallery Image
      Write-Host "Deleting VM Gallery Image" -ForegroundColor Green -BackgroundColor Black
      az azurestackhci galleryimage delete --subscription $subscription --resource-group $resource_group --name "Server22AECore" --yes
 
      #Remove Custom  Location
      Write-Host "Deleting Custom Location" -ForegroundColor Green -BackgroundColor Black
      az customlocation delete --resource-group $resource_group --name $customlocname --yes
      az k8s-extension delete --cluster-type appliances --cluster-name $resource_name --resource-group $resource_group --name $aksoperatorname --yes
      az k8s-extension delete --cluster-type appliances --cluster-name $resource_name --resource-group $resource_group --name $operatorname --yes
    }

}

function cleanupMocRB {

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
        Write-Warning "Removing Arc Resource Bridge Appliance!"
        az arcappliance delete hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml --yes

        Write-Warning "This will remove all Arc Resource Bridge Files, you will need to re-install Arc Resource Bridge"
        Remove-ArcHciConfigFiles

        Remove-item C:\clusterstorage\aks\resourcebridge -Force -Recurse
        
        Write-Warning "This will Uninstall MOC from the Cluster"
        Uninstall-moc
    }
}

function monitorclusterstate {
    param ()
    $clusterstate=Get-ClusterResource -Name "Cluster IP Address" -Cluster $config.ClusterName 
  
  if ($clusterstate.State -ne "online" ) {
    Write-Host "Cluster is not ready yet, starting resources" -ForegroundColor Green -BackgroundColor Black
    Get-ClusterResource -Name "Cluster IP Address" -Cluster $config.ClusterName | start-Clusterresource 
  }
  
    elseif ($clusterstate.State -eq "online" ) {
        Write-Host "Cluster is  ready" -ForegroundColor Green -BackgroundColor Black
    }

}

function checkresourcegroup {
    param()
$resourcegroup=Get-AzResourceGroup -Name $config.resbridgeresource_group -Location $config.Location
if ($resourcegroup.provisioningstate -eq "Succeeded") {
    Write-Host "Resource Group for Arc Resource Bridge has been pre-created" -ForegroundColor Black -BackgroundColor Green
} 
elseif ($resourcegroup.provisioningstate -ne "Succeeded") {
    New-AzResourceGroup -Name $config.resbridgeresource_group -Location $config.Location
}   
}



#End Function Region

#Begin Main Region

<#---------------------------------------------------------------------------------------------------------------#>


$config=LoadVariables
$ServerList = $config.Node01, $config.Node02



RetrieveCredentials
ConfigureWorkstation
ConfigureNodes
ConfigureNode01
ConfigureNode02
PrepareStorage
CreateCluster
DeployS2D
EnableCAU
CreateCSV
CreateCloudWitness
SetNetintents
#Deploying with AAD Account
registerhcicluster

#Deploying with SPN Account
RegisterHCIClusterwithSPN
enableHybridUseBenefit

#If Deploying AKS Hybrid & Arc Resource Bridge run these functions
copyAKSRBInstall
runAKSRBInstall
addcustomlocation_ConnectedK8s

#If deploying MOC+Arc RB run these functions
copyMOCRBInstall
checkresourcegroup
runMocRBInstall
addcustomlocation_ProvisonedK8s




    
    
    
    
    
    
    
    
    
    
    
    
    





























# Main execution begins here







write-host -ForegroundColor Green -Object "Cluster is Deployed; Enjoy!"

#Appendix

