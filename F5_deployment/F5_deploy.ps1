#region SECRET VARIABLES

[string]$SubscriptionId = ""
[string]$TenantId = ""

[string]$HomeIP = ""

if (!(Get-Location).Path.EndsWith("/F5_deployment")) {

    try {
        Set-Location -Path (Join-Path -Path (Get-Location).Path -ChildPath "F5_deployment") -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Cannot change directory to:  F5_deployment"
        Exit
    }

}

try {
    . (Join-Path -Path (Get-Location).Path -ChildPath "F5_deploy_secrets.ps1") -ErrorAction Stop
}
catch {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Cannot load secrets file:  F5_deploy_secrets.ps1"
    Exit
}

#endregion

#region TRANSCRIPT START

Start-Transcript -LiteralPath (Join-Path -Path (Get-Location).Path -ChildPath "F5_deploy.log") -Append -IncludeInvocationHeader 

#endregion

#region VARIABLES

# Update-AzConfig -DisplayBreakingChangeWarning $false

$TagF5Testing = @{"INTENDED_USE"="F5testing"}

$LocationName = "westeurope"

$ResourceGroupName = "F5testingRG"

$StorageAccountName = "f5testingsa"
# Storage account name must be between 3 and 24 characters in length and use numbers and lower-case letters only.
$StorageShareName = "iso"
$StorageShareDirectoryName = "F5"
$F5ISOFileLocalPath = "$HOME/Uploads/14.1.4.5/"
$F5ISOFile = "BIGIP-14.1.4.5-0.0.7.iso"
$StorageShareAccessPolicyName = "F5ISOReadOnlyPolicy"

$NetworkVNetName = "F5testingVNET"
$NetworkVNetPrefix = "192.168.100.0/24"
$NewtorkSubnetNameF5 = "F5subnet"
$NetworkSubnetPrefixF5 = "192.168.100.0/27"
$NetworkNSGNameF5 = "F5testNSG"

$F5IPPublicName = "F5PublicIP"
$F5IPConfigName = "F5IPConfig"
$F5NICName = "F5NIC"
$F5IPAddress = "192.168.100.10"

$F5MDName = "F5MD-OS"

$F5VMName = "F5VM"
# $F5VMSize = "Standard_B2ms"
$F5VMSize = "Standard_E2ads_v5"

$F5VMUser = "azureuser"

#endregion

#region FUNCTIONS

function Register-IdemAzResourceProvider {

    <#
    .SYNOPSIS
        Registers an Azure resource provider if not registered yet in a specified location.

    .DESCRIPTION
        It is an idempotent funtion to register specified Azure resource provider.

    .PARAMETER ResourceProviderName
        The exact name of a resource provider.

    .PARAMETER LocationName
        The exact Azure location string.

    .EXAMPLE
        Register-IdemAzResourceProvider -ResourceProviderName Microsoft.Storage -Location westeurope

    .INPUTS
        String

    .OUTPUTS
        PSResourceProvider

    .NOTES
        Author:  helpermn
    #>

    [CmdletBinding()]

    param (
        
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$ResourceProviderName,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [string]$LocationName
    )

    PROCESS {

        foreach ($ResourceProviderNamespace in $ResourceProviderName) {
            
            $ResourceProvider = Get-AzResourceProvider -Location $LocationName -ListAvailable | Where-Object {$_.ProviderNamespace -eq $ResourceProviderNamespace}

            if ($ResourceProvider.RegistrationState -eq "NotRegistered")
                {
                    Register-AzResourceProvider -ProviderNamespace $ResourceProvider.ProviderNamespace -ConsentToPermissions $true
                    Write-Host -ForegroundColor Cyan (Get-Date)"-Registering: "$ResourceProvider.ProviderNamespace
                    $ResourceProvider = Get-AzResourceProvider -Location $LocationName -ListAvailable | Where-Object {$_.ProviderNamespace -eq $ResourceProviderNamespace}
                    while ($ResourceProvider.RegistrationState -eq "Registering") {
                        Start-Sleep -Seconds 10
                        $ResourceProvider = Get-AzResourceProvider -Location $LocationName -ListAvailable | Where-Object {$_.ProviderNamespace -eq $ResourceProviderNamespace}
                        Write-Host -ForegroundColor Cyan (Get-Date)"-Registration State: "$ResourceProvider.RegistrationState
                    }
                } else {
                    Write-Host -ForegroundColor Cyan (Get-Date)"-Resource Provider registered: "$ResourceProvider.ProviderNamespace
                }

            Write-Output $ResourceProvider
        }

    }

}

#endregion

#region CONTEXT LOG IN

$Context = Get-AzContext
# Get-AzContext | Format-List
# Get-AzContext -ListAvailable
# Clear-AzContext

if ($null -eq $Context) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Connecting to subscription: "$SubscriptionId
    $Account = Connect-AzAccount -Subscription $SubscriptionId -Tenant $TenantId -ErrorAction Stop
    Write-Host -ForegroundColor Cyan (Get-Date)"-Logged in user: "$Account.Context.Account.Id
    # Disconnect-AzAccount
} else {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Already connected user: "$Context.Account
}

$Context = Set-AzContext -Subscription $SubscriptionId -Tenant $TenantId -ErrorAction Stop
Write-Host -ForegroundColor Cyan (Get-Date)"-Context: "$Context.Name

# $AzureSubscription=Get-AzSubscription
# Write-Host -ForegroundColor Cyan (Get-Date)"-Subscription: "$AzureSubscription.Name

$Location = Get-AzLocation | Where-Object Location -EQ $LocationName
Write-Host -ForegroundColor Cyan (Get-Date)"-Default location: "$Location.DisplayName

#endregion

#region RESOURCE GROUP

$ResourceGroup = Get-AzResourceGroup -Location $LocationName -Name $ResourceGroupName -ErrorAction SilentlyContinue
if ($null -eq $ResourceGroup)
    {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Create Resource Group: "$ResourceGroupName
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $LocationName -Tag $TagF5Testing
        # Remove-AzResourceGroup -Id $ResourceGroup.ResourceId
    }
    else {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Resource Group exists: "$ResourceGroupName
    }

# Get-AzResourceGroup -Tag $TagF5Testing

#endregion

#region STORAGE ACCOUNT

$ResourceProvider = Register-IdemAzResourceProvider -ResourceProviderName "Microsoft.Storage" -LocationName $LocationName -ErrorAction SilentlyContinue

$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue

if ($null -eq $StorageAccount)
    {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Create Storage Account: "$StorageAccountName
        $StorageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -SkuName Standard_LRS -Location $LocationName -Tag $TagF5Testing -AllowBlobPublicAccess $false
        # Remove-AzStorageAccount -Id $StorageAccount.ResourceId
    }
    else {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Storage Account exists: "$StorageAccountName
    }

$StorageShare = Get-AzStorageShare -Name $StorageShareName -Context $StorageAccount.Context -ErrorAction SilentlyContinue

if ($null -eq $StorageShare)
    {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Create Storage Share: "$StorageShareName
        $StorageShare = New-AzStorageShare -Name $StorageShareName -Context $StorageAccount.Context
        Set-AzStorageShareQuota -Share $StorageShare.CloudFileShare -QuotaGiB 10 | Out-Null
        Update-AzRmStorageShare -StorageAccount $StorageAccount -Name $StorageShareName -AccessTier Hot | Out-Null
    }
    else {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Storage Share exists: "$StorageShareName
    }

$StorageDirectory = Get-AzStorageFile -Share $StorageShare.CloudFileShare -Path $StorageShareDirectoryName -ErrorAction SilentlyContinue

if ($null -eq $StorageDirectory)
    {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Create Storage Directory: "$StorageShareDirectoryName
        $StorageShareDirectory = New-AzStorageDirectory -Context $StorageAccount.Context -ShareName $StorageShareName -Path $StorageShareDirectoryName
    } else {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Storage Directory exists: "$StorageShareDirectory.Name
    }


$StorageFile = Get-AzStorageFile -Share $StorageShare.CloudFileShare -Path "$StorageShareDirectoryName/$F5ISOFile" -ErrorAction SilentlyContinue

if ($null -eq $StorageFile)
    {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Create Storage File: "$F5ISOFile
        Set-AzStorageFileContent -Context $StorageAccount.Context -ShareName $StorageShareName -Source "$F5ISOFileLocalPath$F5ISOFile" -Path "$StorageShareDirectoryName/$F5ISOFile"
        $StorageFile = Get-AzStorageFile -Share $StorageShare.CloudFileShare -Path "$StorageShareDirectoryName/$F5ISOFile" -ErrorAction SilentlyContinue
    } else {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Storage File exists: "$StorageFile.Name
    }

$StorageShareAccessPolicy = Get-AzStorageShareStoredAccessPolicy -ShareName $StorageShare.Name -Context $StorageAccount.Context -Policy $StorageShareAccessPolicyName -ErrorAction SilentlyContinue

if ($null -eq $StorageShareAccessPolicy)
    {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Create Storage Policy: "$StorageShareAccessPolicyName
        $StorageShareAccessPolicy = New-AzStorageShareStoredAccessPolicy -Policy $StorageShareAccessPolicyName -Permission r -StartTime (Get-Date) -ExpiryTime (Get-Date).AddHours(1) -Context $StorageAccount.Context -ShareName $StorageShareName
    } else {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Storage Policy exists: "$StorageShareAccessPolicyName
        Write-Host -ForegroundColor Cyan (Get-Date)"-Set Storage Policy: ExpiryTime now + 1h"
        $StorageShareAccessPolicy = Set-AzStorageShareStoredAccessPolicy -Policy $StorageShareAccessPolicyName -ShareName $StorageShareName -Context $StorageAccount.Context -ExpiryTime (Get-Date).AddHours(1)
    }

$F5ISOToken = New-AzStorageFileSASToken -File $StorageFile.CloudFile -Protocol HttpsOnly -Policy $StorageShareAccessPolicyName -FullUri
Write-Host -ForegroundColor Cyan (Get-Date)"-URI to F5 ISO file: "$F5ISOToken
# Set-AzStorageShareStoredAccessPolicy -Policy $StorageShareAccessPolicyName -ShareName $StorageShareName -Context $StorageAccount.Context -ExpiryTime (Get-Date)
# Set-AzStorageShareStoredAccessPolicy -Policy $StorageShareAccessPolicyName -ShareName $StorageShareName -Context $StorageAccount.Context -ExpiryTime (Get-Date).AddMinutes(5)

#endregion

#region NETWORKING

# was not needed
# $ResourceProvider = Register-IdemAzResourceProvider -ResourceProviderName "Microsoft.Network" -LocationName $LocationName

$NetworkVNet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName | Where-Object {$_.Name -eq $NetworkVNetName}

if ($null -eq $NetworkVNet) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Create Virtual Network: "$NetworkVNetName
    $NetworkVNet = New-AzVirtualNetwork -Name $NetworkVNetName -ResourceGroupName $ResourceGroupName -Location $LocationName -AddressPrefix $NetworkVNetPrefix -Tag $TagF5Testing
} else {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Virtual Network exists: "$NetworkVNet.Name
}

$NetworkSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $NetworkVNet | Where-Object {$_.Name -eq $NewtorkSubnetNameF5}

if ($null -eq $NetworkSubnet) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Create Subnet: "$NewtorkSubnetNameF5
    $NetworkVNet = Add-AzVirtualNetworkSubnetConfig -Name $NewtorkSubnetNameF5 -VirtualNetwork $NetworkVNet -AddressPrefix $NetworkSubnetPrefixF5
    $NetworkVNet = Set-AzVirtualNetwork -VirtualNetwork $NetworkVNet
    $NetworkSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $NetworkVNet | Where-Object {$_.Name -eq $NewtorkSubnetNameF5}
} else {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Subnet exists: "$NetworkSubnet.Name
}

$NetworkNSG = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName | Where-Object {$_.Name -eq $NetworkNSGNameF5}

if ($null -eq $NetworkNSG) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Create NSG: "$NetworkNSGNameF5
    $NetworkNSGRuleSSH = New-AzNetworkSecurityRuleConfig -Name rule-ssh -Description "SSH access from MNO" -Protocol 'TCP' -DestinationAddressPrefix * -DestinationPortRange 22 -SourceAddressPrefix $HomeIP -SourcePortRange * -Access Allow -Direction Inbound -Priority 100
    $NetworkNSGRuleWEBUI = New-AzNetworkSecurityRuleConfig -Name rule-webui -Description "WEBUI access from MNO" -Protocol 'TCP' -DestinationAddressPrefix * -DestinationPortRange 8443 -SourceAddressPrefix $HomeIP  -SourcePortRange * -Access Allow -Direction Inbound -Priority 200 
    $NetworkNSG = New-AzNetworkSecurityGroup -Name $NetworkNSGNameF5 -ResourceGroupName $ResourceGroupName -Location $LocationName -SecurityRules $NetworkNSGRuleSSH,$NetworkNSGRuleWEBUI -Tag $TagF5Testing
} else {
    Write-Host -ForegroundColor Cyan (Get-Date)"-NSG exists: "$NetworkNSG.Name
}

if ($null -eq $NetworkSubnet.NetworkSecurityGroup) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Attach NSG to Subnet: "$NetworkNSG.Name" -> "$NetworkSubnet.Name
    Set-AzVirtualNetworkSubnetConfig -Name $NewtorkSubnetNameF5 -VirtualNetwork $NetworkVNet -AddressPrefix $NetworkSubnet.AddressPrefix -NetworkSecurityGroupId $NetworkNSG.Id | Out-Null
    $NetworkVNet | Set-AzVirtualNetwork | Out-Null
} else {
    Write-Host -ForegroundColor Cyan (Get-Date)"-NSG attached to Subnet: "$NetworkNSG.Name" -> "$NetworkSubnet.Name
}

$F5IPPublic = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object {$_.Name -eq $F5IPPublicName}

if ($null -eq $F5IPPublic) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Create PIP: "$F5IPPublicName
    $F5IPPublic = New-AzPublicIpAddress -Name $F5IPPublicName -ResourceGroupName $ResourceGroupName -Location $LocationName -Sku Standard -AllocationMethod Static -Tag $TagF5Testing
    $F5IPPublicAddress=$F5IPPublic.IpAddress
    Write-Host -ForegroundColor Cyan (Get-Date)"-New PIP: "$F5IPPublicAddress
} else {
    $F5IPPublicAddress=$F5IPPublic.IpAddress
    Write-Host -ForegroundColor Cyan (Get-Date)"-PIP exists: "$F5IPPublicAddress
}

$F5NIC = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName | Where-Object {$_.Name -eq $F5NICName}

if ($null -eq $F5NIC) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Create IPConfig: "$F5IPConfigName
    $F5IPConfig = New-AzNetworkInterfaceIpConfig -Name $F5IPConfigName -PrivateIpAddressVersion IPv4 -PrivateIpAddress $F5IPAddress -Primary -Subnet $NetworkSubnet -PublicIpAddress $F5IPPublic
    Write-Host -ForegroundColor Cyan (Get-Date)"-Create NIC: "$F5NICName
    $F5NIC = New-AzNetworkInterface -Name $F5NICName -ResourceGroupName $ResourceGroupName -Location $LocationName -IpConfiguration $F5IPConfig -Tag $TagF5Testing
} else {
    Write-Host -ForegroundColor Cyan (Get-Date)"-NIC exists: "$F5NIC.Name
}

#endregion

#region VM

$F5VMImage = Get-AzVMImage -Location $LocationName -PublisherName "f5-networks" -Offer "f5-big-ip-byol" -Skus "f5-big-all-2slot-byol" -Version "16.1.5020000"
$F5AgreementTerms = Get-AzMarketplaceTerms -Name $F5VMImage.PurchasePlan.Name -Product $F5VMImage.PurchasePlan.Product -Publisher $F5VMImage.PurchasePlan.Publisher -SubscriptionId $SubscriptionId -OfferType 'virtualmachine'

if (!$F5AgreementTerms.Accepted) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Accepting Marketplace Terms: "$F5VMImage.PurchasePlan.Publisher" - "$F5VMImage.PurchasePlan.Product" - "$F5VMImage.PurchasePlan.Name
    $F5AgreementTerms = Set-AzMarketplaceTerms -Name $F5VMImage.PurchasePlan.Name -Product $F5VMImage.PurchasePlan.Product -Publisher $F5VMImage.PurchasePlan.Publisher -SubscriptionId $SubscriptionId -Accept
    Write-Host -ForegroundColor Cyan (Get-Date)"-Accepting Marketplace Terms: "$F5AgreementTerms.Accepted
} else {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Accepted Marketplace Terms: "$F5AgreementTerms.Publisher" - "$F5AgreementTerms.Product" - "$F5AgreementTerms.Name
}

$F5VM = Get-AzVM -ResourceGroupName $ResourceGroupName | Where-Object {$_.Name -eq $F5VMName}

if ($null -eq $F5VM) {
    
    Write-Host -ForegroundColor Cyan (Get-Date)"-Create VM: "$F5VMName
    Write-Host -ForegroundColor Cyan (Get-Date)"-Username: "$F5VMUser

    $F5VMPassPlain = ""
    $stringAsStream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($stringAsStream)
    foreach ($passData in ($SubscriptionId, $TenantId)) {
        $writer.write($F5VMPassPlain+(Get-Random -Count 78 | Join-String)+$passData)
        $writer.Flush()
        $stringAsStream.Position = 0
        $F5VMPassPlain = (Get-FileHash -InputStream $stringAsStream -Algorithm SHA256).Hash
        $stringAsStream.SetLength(0)
    }
    $F5VMPassPlain = $F5VMPassPlain+($F5VMPassPlain.ToLower() -replace '\d', '').Substring(0,1)
    Write-Host -ForegroundColor Cyan (Get-Date)"-Password: "$F5VMPassPlain
    
    $F5VMPass = ConvertTo-SecureString $F5VMPassPlain -AsPlainText -Force
    $F5Credential = New-Object System.Management.Automation.PSCredential ($F5VMUser, $F5VMPass)
    
    $F5VM = New-AzVMConfig -VMName $F5VMName -VMSize (Get-AzVMSize -Location $LocationName | Where-Object {$_.Name -eq $F5VMSize}).Name -Tags $TagF5Testing
    $F5VM = Set-AzVMOperatingSystem -VM $F5VM -Linux -ComputerName $F5VMName -Credential $F5Credential
    $F5VM = Add-AzVMNetworkInterface -VM $F5VM -Id $F5NIC.Id
    $F5VM = Set-AzVMOSDisk -VM $F5VM -Name $F5MDName -CreateOption FromImage -DiskSizeInGB 127 -StorageAccountType StandardSSD_LRS -DeleteOption Delete -Linux
    $F5VM = Set-AzVMBootDiagnostic -VM $F5VM -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Enable
    # Get-AzVMImagePublisher -Location $LocationName | Select PublisherName
    # Get-AzVMImageOffer -Location $LocationName -PublisherName "f5-networks"
    # Get-AzVMImageSku -Location $LocationName -PublisherName "f5-networks" -Offer "f5-big-ip-byol"
    # Get-AzVMImage -Location $LocationName -PublisherName "f5-networks" -Offer "f5-big-ip-byol" -Skus "f5-big-all-2slot-byol"
    # Get-AzVMImage -Location $LocationName -PublisherName "f5-networks" -Offer "f5-big-ip-byol" -Skus "f5-big-all-2slot-byol" -Version "16.1.303000"
    $F5VM = Set-AzVMSourceImage -VM $F5VM -PublisherName "f5-networks" -Offer "f5-big-ip-byol" -Skus "f5-big-all-2slot-byol" -Version "16.1.5020000"
    $F5VM = Set-AzVMPlan -VM $F5VM -Name $F5AgreementTerms.Name -Product $F5AgreementTerms.Product -Publisher $F5AgreementTerms.Publisher
    $F5VM = New-AzVM -ResourceGroupName $ResourceGroupName -Location $LocationName -VM $F5VM

} else {

    Write-Host -ForegroundColor Cyan (Get-Date)"-VM exists: "$F5VM.Name
    Write-Host -ForegroundColor Cyan (Get-Date)"-Password: "$F5VMPassPlain

}

#endregion

#region MANAGED DISK

while ($F5VM.ProvisioningState -ne "Succeeded") {
    $F5VM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $F5VMName
    Write-Host -ForegroundColor Cyan (Get-Date)"-VM Provisioning State: "$F5VM.ProvisioningState
    Start-Sleep -Seconds 10
}

$F5MD = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $F5VM.StorageProfile.OsDisk.Name

if ($null -eq $F5MD) {
    Write-Host -ForegroundColor Cyan (Get-Date)"-Managed Disk does not exist: "$F5MDName
} else {
    if ($F5MD.NetworkAccessPolicy -ne 'DenyAll' -or $F5MD.PublicNetworkAccess -ne 'Disabled') {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Stopping VM: "$F5VMName
        Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $F5VMName -Force
        Write-Host -ForegroundColor Cyan (Get-Date)"-Protecting Managed Disk Config: "$F5MD.Name
        $F5MD.NetworkAccessPolicy = 'DenyAll'
        $F5MD.PublicNetworkAccess = 'Disabled'
        $F5MD = Update-AzDisk -ResourceGroupName $ResourceGroupName -Disk $F5MD -DiskName $F5MD.Name
        Write-Host -ForegroundColor Cyan (Get-Date)"-Starting VM: "$F5VMName
        Start-AzVM -ResourceGroupName $ResourceGroupName -Name $F5VMName
    } else {
        Write-Host -ForegroundColor Cyan (Get-Date)"-Managed Disk Protected: "$F5MDName
    }
}

#endregion

#region TRANSCRIPT STOP

Stop-Transcript

#endregion