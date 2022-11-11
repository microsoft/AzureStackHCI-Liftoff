

@{


# This is the PowerShell datafile used to provide configuration information for the Azure Stack HCI Cluster Deployment.

# Version 1.0.0

#Node Parameters
Node01 = "" #Set Short Name for Node01
Node02 = "" #Set Short Name for Node02

node01_MgmtIP="" #Set MGMT IP address for Node01
node02_MgmtIP="" #Set MGMT IP address for Node02

MGMTSubnet="" #Please provide MGMT Subnet
GWIP = "" #Set Default Gateway IP for MGMT Network

ADDomain = "contoso.local" #Please provide domain FQDN
DNSIP = "" #Set DNS IP(s) for DNS servers i.e. Domain Controllers



#Cluster Paramters
ClusterName = "" #Set Short name of Cluster. This account can be Prestaged in Active Directory, just make sure it is "Disabled."
ClusterIP = "" #Provide Cluster IP Address

#Storage Spaces Direct Paramters
StoragePoolName= "Storage Pool 1" #Provide Desired Friendly name of Storage Pool

CSVFriendlyname="Volume01-Thin" #Provide First Cluster Shared Volume Friendly Name, this will be created as a Nested-2-Way Mirror Volume by default.
CSVSize=100GB #Size in GB of First Cluster Shared Volume, Remember Nested-2 Way Mirror is a Storage Efficency of 25%, so 1 TB uses 4 TB of the Storage Pool.

#######################################################################################
    #AKS-HCI parameters
    AKSEnable="true"
    AKSvnetname = "vnet1"
    AKSvSwitchName = ""
    AKSNodeStartIP = ""
    AKSNodeEndIP = ""
    AKSVIPStartIP = ""
    AKSVIPEndIP = ""
    AKSIPPrefix = ""
    AKSGWIP = ""
    AKSDNSIP = ""
    AKSImagedir = "c:\clusterstorage\Volume01\Images"
    AKSWorkingdir = "c:\clusterstorage\Volume01\Workdir"
    AKSCloudConfigdir = "c:\clusterstorage\Volume01\Config"
    AKSCloudSvcidr = ""
    AKSResourceGroupName = ""
    
######################## Set Arc Resource Bridge Variables ##########
resbridgeresource_group= "" #pre-created resource group in Azure
Location="eastus" #Available regions include 'eastus', 'eastus2euap' and 'westeurope'
customloc_name=""#name of the custom location, such as HCICluster -cl
resbridgeip=""# provide unique IP address for Resource Bridge


#########################SET ALL  Azure VARIABLES########################### 

AzureSubID = "" #Please Provide Subscription ID Number for Azure Subscription
KeyVault="" #Please Provide Key Vault Name
CloudWitnessShare=""
CloudWitnessKey=""
AzureTenantID="" #Please Provide AAD Tenant ID
AzureSPNAPPId="" #Please Provie SPN APP ID
AzureSPNSecret=""#PLease Provide SPN Secret 



}


