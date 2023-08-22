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
    #[Parameter(Mandatory)]
    #[String] $AKSIPPrefix ,
    [Parameter(Mandatory)]
    #[String] $AKSGWIP ,
    #[Parameter(Mandatory)]
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
    [String] $resbridge_ipaddressprefix,
    [Parameter(Mandatory)]
    [String] $resbridgevlanid,
    [Parameter(Mandatory)]
    [String] $resbridge_gateway
    

) 

function  InstallPreReqs {
    param ()
        Install-PackageProvider -Name NuGet -Force
        Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck
        Install-Module -Name ArcHci -Repository PSGallery -AcceptLicense -Force -RequiredVersion 0.2.24
        
        az extension remove --name arcappliance
        az extension remove --name k8s-configuration
        az extension remove --name k8s-extension
        az extension remove --name customlocation
        az extension remove --name azurestackhci
        az extension add --upgrade --name arcappliance
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
}
function RunMocInstall {
    param ()
        Write-Host "Intializing MOC" -ForegroundColor Black -BackgroundColor Green    
        Initialize-MocNode

        Write-Host "Setting the MOC Configuration" -ForegroundColor Black -BackgroundColor Green
        Set-MocConfig -workingDir  $AKSWorkingdir 
        
        Write-Host "Installing MOC" -ForegroundColor Black -BackgroundColor Green
        Install-Moc

         #Downloading Gallery Image
         Write-Host "Downloading K8s Gallery Image" -ForegroundColor Black -BackgroundColor Green
         Add-ArcHcik8sGalleryImage -k8sVersion 1.22.11 -version 1.0.16.10113
}

function AzLogin {
    param ()
    Write-Host "Logging Into Azure" -ForegroundColor Black -BackgroundColor Green  # Need to change this to utilize a SPN
    az login --use-device-code --tenant $azuretenantid
    Write-Host "Setting AZ Subscription" -ForegroundColor Black -BackgroundColor Green
    az account set --subscription $AzureSubID
}



function  InstallArcRB {
    param()
    Write-Host "Preparing Azure Arc Resource Bridge YAML files for Installation" -ForegroundColor Black -BackgroundColor Green 
	Write-Host $AKSIPPrefix
	Write-Host $CSV_path
    New-Item -Path $CSV_path -ItemType Directory -Name "ResourceBridge" 

	
    $resource_name= ((Get-AzureStackHci).AzureResourceName) + "-arcbridge" 
	import-module archci -RequiredVersion 0.2.21    
    New-ArcHciConfigFiles -subscriptionID $AzureSubID -location $location -resourceGroup $resbridgeresource_group -resourceName $resource_name -workDirectory $csv_path\ResourceBridge -controlPlaneIP $resbridgecpip -vipPoolStart $resbridgecpip -vipPoolEnd $resbridgecpip -k8snodeippoolstart $resbridgeip1 -k8snodeippoolend $resbridgeip2 -gateway $resbridge_gateway -dnsservers $AKSDNSIP -ipaddressprefix $resbridge_ipaddressprefix  -vswitchName $AKSvSwitchName -vnetName $AKSvnetname -vlanid $resbridgevlanid 

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
    az arcappliance show --resource-group $resbridgeresource_group --name $resource_name --query "status" -o tsv
    
    
    Write-Host "Resource Bridge is Installed" -ForegroundColor Green -BackgroundColor Black  

}        

AzLogin
InstallPreReqs
RunMocInstall
InstallArcRB



