
#Main Function Area
function New-PrestagedAsHciCluster
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
          [Parameter(Mandatory=$true)]
          [ValidateNotNull()]
          [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]
          $OrganizationalUnit,

          [Parameter(Mandatory=$true)]
          [ValidateNotNullOrEmpty()]
          [string]
          $ClusterName
    )

    $ErrorActionPreference = "Stop"

    Write-Verbose "Checking computer '$ClusterName' under OU '$($OrganizationalUnit.DistinguishedName)' ..." -Verbose

    $cno = Get-ADComputer -Filter "Name -eq '$ClusterName'" -SearchBase $OrganizationalUnit

    if ($cno)
    {
        Write-Verbose "Found existing computer with name '$ClusterName', skip creation."
    }
    else 
    {
        Write-Verbose "Creating computer '$ClusterName' under OU '$($OrganizationalUnit.DistinguishedName)' ..." -Verbose
        $cno = New-ADComputer -Name $ClusterName -Description 'Cluster Name Object of HCI deployment' -Path $OrganizationalUnit.DistinguishedName -Enabled $false -PassThru -Verbose
    }

    $cno | Set-ADObject -ProtectedFromAccidentalDeletion:$true -Verbose

    Write-Verbose "Configuring permission for computer '$ClusterName' ..." -Verbose

    $ouPath = "AD:\$($OrganizationalUnit.DistinguishedName)"
    $ouAcl = Get-Acl $ouPath
    $ouAclUpdate = New-Object System.DirectoryServices.ActiveDirectorySecurity

    foreach ($ace in $ouAcl.Access)
    {
        if ($ace.IdentityReference -notlike "*\$ClusterName$")
        {
            $ouAclUpdate.AddAccessRule($ace)
        }
    }

    # Refer to https://docs.microsoft.com/en-us/windows/win32/adschema/c-computer
    $computersObjectType = [System.Guid]::New('bf967a86-0de6-11d0-a285-00aa003049e2')
    $allObjectType = [System.Guid]::Empty
    $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $cno.SID, "CreateChild", "Allow", $computersObjectType, "All"
    $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $cno.SID, "ReadProperty", "Allow", $allObjectType, "All"

    $ouAclUpdate.AddAccessRule($ace1)
    $ouAclUpdate.AddAccessRule($ace2)

    $ouAclUpdate | Set-Acl $ouPath -Verbose

    (Get-Acl $ouPath).Access | Where-Object IdentityReference -like "*\$ClusterName$"

    Write-Verbose "Finish prestage for cluster '$ClusterName'." -Verbose
}
#End Function Area

#Code to Deploy Prestaged Cluster Object, calls Function above. Please update the OU and Cluster names.
$clusterNames = @(
    "PreStaged-ClusterObject"
   
)



#$ou = Get-ADOrganizationalUnit -Filter 'Name -eq "test'
$ou= Get-ADOrganizationalUnit -Identity 'OU=HCI,OU=Servers,DC=Domain,DC=Com'
foreach ($i in $clusterNames)
{
    $ClusterName="$i"
    New-PrestagedAsHciCluster -OrganizationalUnit $ou -ClusterName $i
}