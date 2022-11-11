$akshybrid_extname=$customloc_name += "-aks"

#VM
az k8s-extension create --cluster-type appliances --cluster-name $resource_name --resource-group $resource_group --name hci-vmoperator --extension-type Microsoft.AZStackHCI.Operator --scope cluster --release-namespace default--configuration-settings Microsoft.CustomLocation.ServiceAccount="default" --configuration-protected-settings-file $csv_path\ResourceBridge\hci-config.json --configuration-settings HCIClusterID=$hciClusterId --auto-upgrade true

#AKS
az k8s-extension create --resource-group $resource_group --cluster-name $resource_name --cluster-type appliances --name $akshybrid_extname  --extension-type Microsoft.HybridAKSOperator  --config Microsoft.CustomLocation.ServiceAccount="default"

#ResourceBridge ID
$ArcResourceBridgeId=az arcappliance show --resource-group $resource_group --name $resource_name --query id -o tsv

#VMOperator Extension ID
$vmoperator_ext_id=az k8s-extension show --resource-group $resource_group --cluster-name $resource_name --cluster-type appliances --name hci-vmoperator --query id -o tsv

#HyridAKS Extension ID
$AKSClusterExtensionResourceId=az k8s-extension show --resource-group $resource_group --cluster-name $resource_name --cluster-type appliances --name $akshybrid_extname --query id -o tsv
        
#Update Custom Location with AKS Hybrid Extension
az customlocation create --resource-group $resource_group --name $customloc_name --cluster-extension-ids $AKSClusterExtensionResourceId $vmoperator_ext_id --namespace "default"  --host-resource-id $ArcResourceBridgeId --location $location

#Create VM Operator Virtual Network
Write-Host "Creating Virtual Network Resource for Arc Virtual Machine Management" -ForegroundColor Green -BackgroundColor Black
         #$vlanid="0"   
         $vnetName="default-vnet"
         New-MocGroup -name "Default_Group" -location "MocLocation"
         New-MocVirtualNetwork -name "$vnetName" -group "Default_Group" -tags @{'VSwitch-Name' = "ConvergedSwitch(hci)"} 
         az azurestackhci virtualnetwork create --subscription $subscription --resource-group $resource_group --extended-location name="/subscriptions/$subscription/resourceGroups/$resource_group/providers/Microsoft.ExtendedLocation/customLocations/$customloc_name" type="CustomLocation" --location $Location --network-type "Transparent" --name $vnetName #--vlan $vlanid


#Create HybridAKS VNet
Write-Host "Creating Virtual Network Resource for AKS Hybrid" -ForegroundColor Green -BackgroundColor Black

New-KvaVirtualNetwork -name $AKSVNetName -vswitchName $AKSvSwitchName -ipaddressprefix $AKSIPPrefix -gateway $AKSGWIP -dnsservers 10.255.252.4-vippoolstart $AKSVIPStartIP -vippoolend $AKSVIPEndIP -k8snodeippoolstart $AKSNodeStartIP -k8snodeippoolend $AKSNodeStartIP -kubeconfig $appliancekubeconfig

az hybridaks vnet create -n $aksvnetname -g $resource_group --custom-location "/subscriptions/$subscription/resourceGroups/$resource_group/providers/Microsoft.ExtendedLocation/customLocations/$customloc_name" --moc-vnet-name $aksvnetname

#Download AKS Marinier Image
Add-KvaGalleryImage -kubernetesVersion 1.22.11 

$Location="" #Available regions include 'eastus', 'eastus2euap' and 'westeurope'
$customloc_name="s4010CL"#name of the custom location, such as HCICluster -cl
$resbridgeip="172.25.30.96"# provide unique IP address for Resource Bridge
$resbridgecpip="172.25.30.97" # provide unique IP address for Resource Bridge Control Plane
$AzureSubID = "" #Please Provide Subscription ID Number for Azure Subscription
$AzureTenantID="" #Please Provide AAD Tenant ID
$AzureSPNAPPId= "" #Please Provide SPN APP ID 
$AzureSPNSecret=""#PLease Provide SPN Secret 
    $AKSvnetname = "s4010-vnet"
    $AKSvSwitchName = "ConvergedSwitch(HCI)"
    $AKSNodeStartIP = "172.25.30.100"
    $AKSNodeEndIP = "172.25.30.150"
    $AKSVIPStartIP = "172.25.30.151"
    $AKSVIPEndIP = "172.25.30.200"
    $AKSIPPrefix = "172.25.30.0/24"
    $AKSGWIP = "172.25.30.1"
    $AKSDNSIP = "10.255.252.4","10.255.252.5"
   $AKSCloudSvcidr = "172.25.30.95/24"
    $AKSResourceGroupName = "S4010-aks"