

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
    [String] $AKSvnetname,
    [Parameter(Mandatory)]
    [String] $AKSvSwitchName,
    [Parameter(Mandatory)]
    [String] $AKSNodeStartIP,
    [Parameter(Mandatory)]
    [String] $AKSNodeEndIP,
    [Parameter(Mandatory)]
    [String] $AKSVIPStartIP,
    [Parameter(Mandatory)]
    [String] $AKSVIPEndIP,
    [Parameter(Mandatory)]
    [String] $AKSIPPrefix,
    [Parameter(Mandatory)]
    [String] $AKSGWIP,
    [Parameter(Mandatory)]
    [String] $AKSDNSIP,
    [Parameter(Mandatory)]
    [String] $AKSImagedir,
    [Parameter(Mandatory)]
    [String] $AKSWorkingdir,
    [Parameter(Mandatory)]
    [String] $AKSCloudSvcidr,
    [Parameter(Mandatory)]
    [String] $AKSClusterRoleName,
    [Parameter(Mandatory)]
    [String] $AKSResourceGroupName,
    [Parameter(Mandatory)]
    [String] $Location,
    [Parameter(Mandatory)]
    [String] $resbridgeresource_group,
    [Parameter(Mandatory)]
    [String] $resbridgeip1,
    [Parameter(Mandatory)]
    [String] $resbridgeip2,  
    [Parameter(Mandatory)]
    [String] $resbridgecpip,
    [Parameter(Mandatory)]
    [String] $csv_path,
    [Parameter(Mandatory)]
    [String] $aksvlan
    
    

) 

function ConnectAzureSPN {
    param ()
    Write-Host "Logging into your Azure Account" -ForegroundColor Black -BackgroundColor Green
    Connect-AzAccount -Subscription $AzureSubID -Tenant $AzureTenantID -UseDeviceAuthentication

    Write-Host "Getting Azure SPN Credentials" -ForegroundColor Black -BackgroundColor Green
    $sp=Get-AzADServicePrincipal -ApplicationId $AzureSPNAppID
    $spnsecure=ConvertTo-SecureString -String $AzureSPNSecret -AsPlainText -Force
    $spnCred = New-Object System.Management.Automation.PSCredential ($sp.AppId, $spnsecure)
}

Function InstallModules {
param ()
    Write-Host "Importing Required PowerShellGet Modules to start Deployment" -ForegroundColor Green -BackgroundColor Black
    Install-Module PowerShellGet -AllowClobber -Force
    Import-Module PowerShellGet -Force -MinimumVersion 2.0.0
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
   

 Write-Host "Installing Required Modules" -ForegroundColor Green -BackgroundColor Black
    
    $ModuleNames="Az.Resources","Az.Accounts", "AzureAD", "AKSHCI", "Az.keyvault"
    foreach ($ModuleName in $ModuleNames){
        if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
            Install-Module -Name $ModuleName -Force -AcceptLicense 
        }
    }
    Import-Module Az.keyvault
    Import-Module Az.Accounts
    Import-Module Az.Resources -MinimumVersion 2.6.0
    Import-Module AzureAD
    Import-Module AksHci -MinimumVersion 1.1.83
    
    
}


function DeployAKS {
    param ()



#$azurecred=Connect-AzAccount -Subscription $AzureSubID -Tenant $AzureTenantID -UseDeviceAuthentication





Write-Host "Prepping AKS Install"
    Write-Host "Setting AKS Virtual Network on HCI Cluster" -ForegroundColor Black -BackgroundColor Green  
    Initialize-AksHciNode
    
    Write-Host "Setting AKS Virtual Network on HCI Cluster" -ForegroundColor Black -BackgroundColor Green   
    $vnet = New-AksHciNetworkSetting -name $AKSvnetname -vSwitchName $AKSvSwitchName -k8sNodeIpPoolStart $AKSNodeStartIP -k8sNodeIpPoolEnd $AKSNodeEndIP -vipPoolStart $AKSVIPStartIP -vipPoolEnd $AKSVIPEndIP -ipAddressPrefix $AKSIPPrefix -gateway $AKSGWIP -dnsServers $AKSDNSIP -VLanid $aksvlan

    Write-Host "Setting AKS-MOC Configuration" -ForegroundColor Black -BackgroundColor Green
    Write-Host "Deploying AKS-Hybrid with $AKSClusterRoleName" -ForegroundColor Black -BackgroundColor Green

    Set-AksHciConfig -imageDir $AKSImagedir -workingDir $AKSWorkingdir -cloudConfigLocation $AKSCloudConfigdir -vnet $vnet -cloudservicecidr $AKSCloudSvcidr -clusterRoleName $AKSClusterRoleName 
    
    Write-Host $AKSResourceGroupName -ForegroundColor Green -BackgroundColor Black

    Write-Host "Setting AKS Registration in Azure" -ForegroundColor Black -BackgroundColor Green 
    Set-AksHciRegistration -subscriptionId $AzureSubID -resourceGroupName $AKSResourceGroupName -Tenant $AzureTenantID  -UseDeviceAuthentication

    #With SPN
    Set-AksHciRegistration -SubscriptionId $AzureSubID -ResourceGroupName $AKSResourceGroupName -TenantId $AzureTenantID -Credential $spnCred
    
    Write-Host "Ready to Install AKS on HCI Cluster"
    Install-AksHci



}


Function InstallArcRB {
param ()
Write-Host "Logging into your Azure Account" -ForegroundColor Black -BackgroundColor Green 
#$azureAppCred = (New-Object System.Management.Automation.PSCredential $AzureSPNAPPId, (ConvertTo-SecureString -String $AzureSPNSecret -AsPlainText -Force))
#Connect-AzAccount -ServicePrincipal -Subscription $AzureSubID -Tenant $AzureTenantID -Credential $azureAppCred
#Connect-AzAccount -ServicePrincipal -Subscription $AzureSubID -Tenant $AzureTenantID -UseDeviceAuthentication




#Install AZ Resource Bridge
Write-Host "Now Preparing to Install Azure Arc Resource Bridge" -ForegroundColor Black -BackgroundColor Green 

#Install Required Modules 

Install-PackageProvider -Name NuGet -Force 
Install-Module -Name PowershellGet -Force -MinimumVersion 2.0.0 -Confirm:$false -SkipPublisherCheck
Install-Module -Name ArcHci -Force -Confirm:$false -SkipPublisherCheck -AcceptLicense



#Install AZ CLI
Write-Host "Installing Azure CLI" -ForegroundColor Black -BackgroundColor Green 
$ProgressPreference = 'SilentlyContinue'; 
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; 
Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi



#Install Required Extensions
Write-Host "Preparing Required Extensions" -ForegroundColor Black -BackgroundColor Green 
az extension remove --name arcappliance
az extension remove --name connectedk8s
az extension remove --name k8s-configuration
az extension remove --name k8s-extension
az extension remove --name customlocation
az extension remove --name azurestackhci
#az extension add --upgrade --name arcappliance   REMOVED for TEMP WORKAROUND TO KNOWN BUG 
az extension add --version 0.2.29 --name arcappliance
az extension add --upgrade --name connectedk8s
az extension add --upgrade --name k8s-configuration
az extension add --upgrade --name k8s-extension
az extension add --upgrade --name customlocation
az extension add --upgrade --name azurestackhci

az provider register --namespace Microsoft.Kubernetes --wait
az provider register --namespace Microsoft.KubernetesConfiguration --wait
az provider register --namespace Microsoft.ExtendedLocation --wait
az provider register --namespace Microsoft.ResourceConnector --wait
az provider register --namespace Microsoft.AzureStackHCI --wait
az provider register --namespace Microsoft.HybridConnectivity --wait




$resource_name= ((Get-AzureStackHci).AzureResourceName) + "-arcbridge"

mkdir $csv_path\ResourceBridge

#az login --service-principal -u $AzureSPNAPPId -p $AzureSPNSecret --tenant $AzureTenantID

az login --use-device-code --tenant $azuretenantid

az account set --subscription $AzureSubID

 

New-ArcHciConfigFiles -subscriptionID $AzureSubID -location $location -resourceGroup $resbridgeresource_group -resourceName $resource_name -workDirectory $csv_path\ResourceBridge -controlPlaneIP $resbridgecpip -vipPoolStart $resbridgecpip -vipPoolEnd $resbridgecpip -k8snodeippoolstart $resbridgeip1 -k8snodeippoolend $resbridgeip2 -gateway $AKSGWIP -dnsservers $AKSDNSIP -ipaddressprefix $AKSIPPrefix  -vswitchName $AKSvSwitchName -vLanID $aksvlanid

Write-Host "Validating Azure Arc Resource Bridge" -ForegroundColor Black -BackgroundColor Green 

az arcappliance validate hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml

 
Write-Host "Preparing Arc Resource Bridge" -ForegroundColor Black -BackgroundColor Green 

az arcappliance prepare hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml


Write-Host "Deploying Arc Resource Bridge" -ForegroundColor Black -BackgroundColor Green 
az arcappliance deploy hci --config-file  $csv_path\ResourceBridge\hci-appliance.yaml --outfile  $csv_path\ResourceBridge\config\

Write-Host "Creating Arc Resource Bridge" -ForegroundColor Black -BackgroundColor Green 

az arcappliance create hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml --kubeconfig $csv_path\ResourceBridge\config\

Write-Host "Waiting for Arc Resource Bridge to come online" -ForegroundColor Green -BackgroundColor Black

Start-Sleep 180
 
 Write-Host "Resource Bridge is Installed" -ForegroundColor Green -BackgroundColor Black  
}


#Main 

ConnectAzureSPN
InstallModules
DeployAKS
InstallArcRB