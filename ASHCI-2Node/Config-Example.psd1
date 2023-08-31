

@{


    # This is the PowerShell datafile used to provide configuration information for the Azure Stack HCI Cluster Deployment.
    
    # Version 1.0.0
    
    #Node Parameters
    Node01 = "node1" #Set Short Name for Node01
    Node02 = "node2" #Set Short Name for Node02
  
    
    node01_MgmtIP="10.88.19.211" #Set MGMT IP address for Node01
    node02_MgmtIP="10.88.19.215" #Set MGMT IP address for Node02
   
    
    MGMTSubnet="10.88.18.0/23" #Please provide MGMT Subnet
    GWIP = "10.88.19.1" #Set Default Gateway IP for MGMT Network
    
    ADDomain = "domain.com" #Please provide domain FQDN
    DNSIP = "192.168.20.1" #Set DNS IP(s) for DNS servers i.e. Domain Controllers
    
    
    
    #Cluster Paramters
    ClusterName = "Demo-CL" #Set Short name of Cluster. This account can be Prestaged in Active Directory, just make sure it is "Disabled."
    ClusterIP = "10.88.19.204" #Provide Cluster IP Address
    
    #Storage Spaces Direct Paramters
    StoragePoolName= "Storage Pool 1" #Provide Desired Friendly name of Storage Pool
    
    CSVFriendlyname="AKS" #Provide First Cluster Shared Volume Friendly Name, this will be created as a Nested-2-Way Mirror Volume by default.
    CSVSize= 600GB #Size in GB of First Cluster Shared Volume, Remember Nested-2 Way Mirror is a Storage Efficency of 25%, so 1 TB uses 4 TB of the Storage Pool.
    csv_path="C:\clusterstorage\AKS"
    #######################################################################################
        #AKS-HCI parameters
        AKSEnable="true"
        AKSvnetname = ""
        AKSvSwitchName = ""
        AKSNodeStartIP = "10.81.5.96"
        AKSNodeEndIP = "10.81.5.127"
        AKSVIPStartIP = "10.81.5.80"
        AKSVIPEndIP = "10.81.5.95"
        AKSIPPrefix = "10.81.5.1/24"
        AKSGWIP = "10.81.5.254"
        AKSDNSIP = "192.168.20.1"
        AKSImagedir = "c:\clusterstorage\AKS\Images"
        AKSWorkingdir = "c:\clusterstorage\AKS\Workdir"
        AKSCloudConfigdir = "c:\clusterstorage\AKS\Config"
        AKSCloudSvcidr = "10.81.5.1/24"
        AKSResourceGroupName = ""
        AKSClusterRoleName = ""
        aksvlan="0"
        
    ######################## Set Arc Resource Bridge Variables ##########
    resbridgeresource_group= "" #pre-created resource group in Azure
    Location="eastus" #Available regions include 'eastus', 'eastus2euap' and 'westeurope'
    customloc_name=""#name of the custom location, such as HCICluster -cl
    resbridgeip1="10.88.19.216"# provide unique IP address for Resource Bridge
    resbridgeip2="10.88.19.217"# provide unique IP address for Resource Bridge
    resbridgecpip="10.88.19.218" # provide unique IP address for Resource Bridge Control Plane
    resbridge_ipaddressprefix="10.88.18.0/23"
    resbridge_vlanid="0"
    resbridge_gateway="10.88.19.254"
    
    ########################## Set Arc Resource Bridge Custom Location Values  ######################
    vmss_vnetname="" #Name for VM Self Service Deployment  Virtual Network
    PEO_AKSCLusterName="" #Name for AKS Cluster
    akshybrid_virtualnetwork=""
    akshybrid_ipaddressprefix="10.81.5.1/24" 
    akshybrid_gateway="10.81.5.254"
    akshybrid_dns="192.168.20.1"
    akshybrid_vippoolstart="10.81.5.80"
    akshybrid_vippoolend="10.81.5.95"
    akshybrid_k8snodeippoolstart="10.81.5.96"
    akshybrid_k8snodeippoolend="10.81.5.127"
    akshybridvlan="302"
    
    #########################SET ALL  Azure VARIABLES########################### 
    
    AzureSubID = "" #Please Provide Subscription ID Number for Azure Subscription
    KeyVault="n/a" #Please Provide Key Vault Name
    CloudWitnessShare=""
    CloudWitnessKey=""
    AzureTenantID="" #Please Provide AAD Tenant ID
    AzureSPNAPPId= "" #Please Provide SPN APP ID 
    AzureSPNSecret=""#PLease Provide SPN Secret 
    
    
    
    
    }
    
    
    