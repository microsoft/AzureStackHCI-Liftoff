

param(
    [Parameter(Mandatory)]
    [String] $AzureSPNAppID,
    [Parameter(Mandatory)]
    [String] $AzureSPNSecret,
    [Parameter(Mandatory)]
    [String] $AzureSubID,
    [Parameter(Mandatory)]
    [String] $AzureTenantID,
    [Parameter(Mandatory)]
    [String] $KeyVault,
    [Parameter(Mandatory)]
    [String] $SecretName,
    [Parameter(Mandatory)]
    [String] $AKSvnetname ,
    [Parameter(Mandatory)]
    [String] $AKSvSwitchName ,
    [Parameter(Mandatory)]
    [String] $AKSNodeStartIP ,
    [Parameter(Mandatory)]
    [String] $AKSNodeEndIP ,
    [Parameter(Mandatory)]
    [String] $AKSVIPStartIP,
    [Parameter(Mandatory)]
    [String] $AKSVIPEndIP ,
    [Parameter(Mandatory)]
    [String] $AKSIPPrefix ,
    [Parameter(Mandatory)]
    [String] $AKSGWIP ,
    [Parameter(Mandatory)]
    [String] $AKSDNSIP,
    [Parameter(Mandatory)]
    [String] $AKSImagedir ,
    [Parameter(Mandatory)]
    [String] $AKSWorkingdir,
    [Parameter(Mandatory)]
    [String] $AKSCloudSvcidr ,
    [Parameter(Mandatory)]
    [String] $AKSResourceGroupName ,
    [Parameter(Mandatory)]
    [String] $Location ,
    [Parameter(Mandatory)]
    [String] $csv_path ,
    [Parameter(Mandatory)]
    [String] $resbridgeresource_group,
    [Parameter(Mandatory)]
    [String] $resbridgeip,  
    [Parameter(Mandatory)]
    [String] $resbridgecpip 
    

) 


Function InstallModules {
param ()

 Write-Host "Installing Required Modules" -ForegroundColor Green -BackgroundColor Black
    
    $ModuleNames="Az.Resources","Az.Accounts", "AzureAD", "AKSHCI", "Az.keyvault"
    foreach ($ModuleName in $ModuleNames){
        if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
            Install-Module -Name $ModuleName -Force -AcceptLicense 
        }
    }
    Import-Module Az.keyvault
    Import-Module Az.Accounts
    Import-Module Az.Resources
    Import-Module AzureAD
    Import-Module AksHci
    
    
}


function DeployAKS {
    param ()

$SecretDetail = Get-AzKeyVaultSecret -VaultName $KeyVault -Name $SecretName -AsPlainText
$azureAppCred= New-Object System.Management.Automation.PSCredential ("$AzureSPNAPPId", $SecretDetail)
#$azureAppCred = (New-Object System.Management.Automation.PSCredential $AzureSPNAPPId, (ConvertTo-SecureString -String $Arcsecretact -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -Subscription $AzureSubID -Tenant $AzureTenantID -Credential $azureAppCred




$context = Get-AzContext 
$armtoken = Get-AzAccessToken
$graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph

Write-Host "Prepping AKS Install"


    

    $vnet = New-AksHciNetworkSetting -name $AKSvnetname -vSwitchName $AKSvSwitchName -k8sNodeIpPoolStart $AKSNodeStartIP -k8sNodeIpPoolEnd $AKSNodeEndIP -vipPoolStart $AKSVIPStartIP -vipPoolEnd $AKSVIPEndIP -ipAddressPrefix $AKSIPPrefix -gateway $AKSGWIP -dnsServers $AKSDNSIP       

    Set-AksHciConfig -imageDir $AKSImagedir -workingDir $AKSWorkingdir -cloudConfigLocation $AKSCloudConfigdir -vnet $vnet -cloudservicecidr $AKSCloudSvcidr 

    $azurecred = Connect-AzAccount -ServicePrincipal -Subscription $AzureSubID  -Tenant $AzureTenantID -Credential $azureAppCred

    #$azurecred = Connect-AzAccount -Subscription $AzureSubID  -Tenant $AzureTenantID -UseDeviceAuthentication
    
    Write-Host $AKSResourceGroupName -ForegroundColor Green -BackgroundColor Black

    Set-AksHciRegistration -subscriptionId $AzureSubID -resourceGroupName $AKSResourceGroupName -Tenant $AzureTenantID -Credential $azurecred

    Write-Host "Ready to Install AKS on HCI Cluster"

    Install-AksHci



}


Function InstallArcRB {
param ()

$SecretDetail = Get-AzKeyVaultSecret -VaultName $KeyVault -Name $SecretName
$azureAppCred= New-Object System.Management.Automation.PSCredential ($AzureSPNAPPId, $SecretDetail.SecretValue)
#$azureAppCred = (New-Object System.Management.Automation.PSCredential $AzureSPNAPPId, (ConvertTo-SecureString -String $ARCSecret -AsPlainText -Force))
#Connect-AzAccount -ServicePrincipal -Subscription $AzureSubID -Tenant $AzureTenantID -Credential $azureAppCred
$context = Get-AzContext # Azure credential
$armtoken = Get-AzAccessToken
$graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph


#Install AZ Resource Bridge
Write-Host "Now Preparing to Install Azure Arc Resource Bridge" -ForegroundColor Black -BackgroundColor Green 

#Install Required Modules 

Install-PackageProvider -Name NuGet -Force 
Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck
Install-Module -Name ArcHci -Force -Confirm:$false -SkipPublisherCheck -AcceptLicense



#Install AZ CLI

$ProgressPreference = 'SilentlyContinue'; 
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; 
Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi



#Install Required Extensions

az extension remove --name arcappliance
az extension remove --name connectedk8s
az extension remove --name k8s-configuration
az extension remove --name k8s-extension
az extension remove --name customlocation
az extension remove --name azurestackhci
az extension add --upgrade --name arcappliance
az extension add --upgrade --name connectedk8s
az extension add --upgrade --name k8s-configuration
az extension add --upgrade --name k8s-extension
az extension add --upgrade --name customlocation
az extension add --upgrade --name azurestackhci



#$csv_path= "C:\clusterstorage\Volume01"
$resource_name= ((Get-AzureStackHci).AzureResourceName) + "-arcbridge"

mkdir $csv_path\ResourceBridge


#az login --service-principal -u $AzureSPNAPPId -p $azureAppCred.GetNetworkCredential().Password --tenant $AzureTenantID

az login --use-device-code --tenant $AzureTenantID --subscription $AzureSubID

New-ArcHciConfigFiles -subscriptionId $AzureSubID -location $Location -resourceGroup $resbridgeresource_group -resourceName $resource_name -workDirectory $csv_path\ResourceBridge -controlPlaneIP $resbridgecpip  -k8snodeippoolstart $resbridgeip -k8snodeippoolend $resbridgeip -gateway $AKSGWIP -dnsservers $AKSDNSIP -ipaddressprefix $AKSIPPrefix   
 
az arcappliance validate hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml

 

az arcappliance prepare hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml



az arcappliance deploy hci --config-file  $csv_path\ResourceBridge\hci-appliance.yaml --outfile  $csv_path\ResourceBridge\config\


az arcappliance create hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml --kubeconfig $csv_path\ResourceBridge\config\

Write-Host "Waiting for Arc Resource Bridge to come online" -ForegroundColor Green -BackgroundColor Black

Start-Sleep 180
 
 Write-Host "Resource Bridge is Installed" -ForegroundColor Green -BackgroundColor Black  
}



InstallModules


$azlogin = Connect-AzAccount -Subscription $azuresubid -UseDeviceAuthentication -TenantId $AzureTenantID 
Select-AzSubscription -Subscription $AzureSubID

$Arcsecretact=Get-AzKeyVaultSecret -VaultName $KeyVault -Name "CPPE-ARC-SPN-Account" -AsPlainText
#$ARCSecret=$arcsecretact.SecretValue




DeployAKS
InstallArcRB
