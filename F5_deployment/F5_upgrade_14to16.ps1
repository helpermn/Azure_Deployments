#region SECRET VARIABLES

[string]$SubscriptionId = ""
[string]$TenantId = ""

[string]$RegistrationKey = ""
[array]$AddonRegistrationKeys = ""

[string]$NewRegistrationKey = ""
[array]$NewAddonRegistrationKeys = ""

#Parameters that should be set by F5_deploy.ps1 If F5_deploy.ps1 has not been run, set them accordingly in F5_deploy_secrets.ps1.

#[string]$F5VMPassPlain = ""

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

#Parameters that should be set by F5_deploy.ps1 If F5_deploy.ps1 has not been run, set them accordingly.

#$ResourceGroupName = ""
#$F5VMName = ""

#$F5ISOFile = ""
#$F5ISOToken = ""

#$F5IPPublicAddress = ""

#$F5VMUser = ""

#endregion

#region FUNCTIONS


function Wait-F5Ready {

    <#
    .SYNOPSIS
        Waits for F5 ready for operation.

    .DESCRIPTION
        It is a function that waits for:
        - 22/tcp port open
        - ready for:
        -- licesing
        -- configuration
        -- provisioning
        -- operation (Active status)

    .PARAMETER ResourceGroupName
        The exact name of a resource group.

    .PARAMETER F5VMNames
        The exact name of a VM.
    
    .PARAMETER WaitFor
        A list of events to wait for:
        - config
        - license
        - provision
        - active
        - all

    .EXAMPLE
        Wait-F5Ready -ResourceGroupName MyRG -VMName MyVM

    .INPUTS
        String, Array

    .OUTPUTS
        String

    .NOTES
        Author:  helpermn
    #>

    [CmdletBinding()]

    param (
        
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$F5VMNames,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [ValidateSet("config", "license", "provision", "active", "all")]
        [array]$ForWhat
    )

    BEGIN {

        [hashtable]$ForWhatParams = @{}

        foreach ($ForWhatParam in $ForWhat) {
            $ForWhatParams.Add($ForWhatParam, $ForWhatParam)
        }
    }

    PROCESS {

        foreach ($VMName in $F5VMNames) {
            
            $VM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName

            $VMPublicIPAddress = (Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object {$_.Id -eq (Get-AzNetworkInterface -ResourceId $VM.NetworkProfile[0].NetworkInterfaces[0].Id).IpConfigurations[0].PublicIpAddress.Id}).IpAddress

            while (!(Test-Connection -ComputerName $VMPublicIPAddress -TcpPort 22)) { Start-Sleep 10 }

            $ScriptString = '#!/bin/bash

            . /etc/bashrc
            . /usr/lib/bigstart/bigip-ready-functions
            
            
            for forWhat in ${*}; do
            
            case "${forWhat}" in
            
            license)        echo -n "Waiting for license..."
                            wait_bigip_ready_license
                            echo "OK";;
            config)         echo -n "Waiting for config..."
                            wait_bigip_ready_config
                            echo "OK";;
            provision)      echo -n "Waiting for provision..."
                            wait_bigip_ready_provision
                            echo "OK";;
            active)         echo -n "Waiting for Active..."
                            while ! getPromptStatus | grep -q "Active"; do sleep 10; done;
                            echo "OK";;
            all)            echo -n "Waiting for all..."
                            wait_bigip_ready_config
                            wait_bigip_ready_license
                            wait_bigip_ready_provision
                            while ! getPromptStatus | grep -q "Active"; do sleep 10; done;
                            echo "OK";;
            *)              echo "Unknown parameter value: ${forWhat}";;
            esac
            
            done;
            '

            $RunCommandOutput = Invoke-AzVMRunCommand -VM $VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $ForWhatParams
            
            Write-Output $RunCommandOutput
            
        }

    }

}

function Restart-F5VM {

    <#
    .SYNOPSIS
        Saves configuration and initiates reboot of F5VE devices.

    .DESCRIPTION
        It is a function that:
        - saves configuration of all partitions
        - stops sshd daemon; established connections are not terminated
        - reboots the device

    .PARAMETER ResourceGroupName
        The exact name of a resource group.

    .PARAMETER F5VMNames
        The exact name of a VM.

    .EXAMPLE
        Restart-F5VM -ResourceGroupName MyRG -VMName MyVM

    .INPUTS
        String

    .OUTPUTS
        String

    .NOTES
        Author:  helpermn
    #>

    [CmdletBinding()]

    param (
        
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$F5VMNames,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [string]$ResourceGroupName
    )

    PROCESS {

        foreach ($VMName in $F5VMNames) {
            
            $VM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName

            $ScriptString = '#!/bin/bash
            
            tmsh save sys config partitions all
            tmsh stop sys service sshd
            reboot
            '

            $RunCommandOutput = Invoke-AzVMRunCommand -VM $VM -CommandId 'RunShellScript' -ScriptString $ScriptString
            
            Write-Output $RunCommandOutput
            
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

#region configure F5

$F5VM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $F5VMName

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat config,provision

# Step 1
# - v16 disk extension and provisioning
# - v14 download, installation, reboot into

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.color { value orange }"
tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress...'' }"
tmsh -c "modify sys db ui.advisory.enabled { value true }"
tmsh -c "modify sys global-settings gui-setup disabled"

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [extending disks and reboot]'' }"
tmsh -c "modify sys disk directory /appdata new-size 33554432"
tmsh -c "modify sys disk directory /var/log new-size 12288000"
tmsh -c "modify sys disk directory /var new-size 9437184"
tmsh -c "modify sys disk directory /config new-size 4546560"
tmsh -c "modify sys disk directory /shared new-size 31457280"
tmsh -c "save sys config partitions all"
tmsh -c "stop sys service sshd"
reboot
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat config,provision

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$F5ScriptParams.Add("ISOFileURL", "'$F5ISOToken'")
$F5ScriptParams.Add("ISOFileName", "'$F5ISOFile'")

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [modules provisioning: LTM]'' }"
tmsh -c "modify sys db provision.extramb { value 500 }"
wait_bigip_ready_provision
wait_bigip_ready_config

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [modules provisioning: APM]'' }"
tmsh -c "modify sys provision apm { level nominal }"
wait_bigip_ready_provision
wait_bigip_ready_config

tmsh -c "modify sys db ui.advisory.text { value ''Onboarding with PowerShell in progress... [downloading ISO file]'' }"
ISOFileSize=$(curl -q -s -I "$ISOFileURL" | grep "Content-Length:" | cut -d " " -f 2 | tr -dc ''[[:digit:]]'')
curl -q -s -o "/shared/images/$ISOFileName" "$ISOFileURL" &
while jobs %1 >/dev/null 2>&1; do
    sleep 10
    currentFileSize=$(stat --format=%s "/shared/images/$ISOFileName" 2>/dev/null | tr -d ''\n'')
    : ${currentFileSize:=0}
    percentDownload=$((currentFileSize*100/ISOFileSize))
    tmsh -c "modify sys db ui.advisory.text { value ''Onboarding with PowerShell in progress... [downloading ISO file, completed ${percentDownload}%]'' }"
done;

tmsh -c "modify sys db ui.advisory.text { value ''Onboarding with PowerShell in progress... [verifying ISO file]'' }"
if ! /usr/bin/checkisomd5 "/shared/images/$ISOFileName" >/dev/null 2>&1; then
    tmsh -c "modify sys db ui.advisory.text { value ''Onboarding with PowerShell in progress... [ISO file verification failed, script stopped]'' }"
    echo -n "ISOVerificationFailed" >&2
    exit 1
fi
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

if ($RunCommandOutput.Value.Message -like "*ISOVerificationFailed*") {
    Write-Host -ForegroundColor Cyan "ISO file verification failed. Please fix the issue manually. When done, press Y and [ENTER] to continue."
    $AskIfContinue = Read-Host
    if ($AskIfContinue -ne "Y") {
        exit
    }
}

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$F5ScriptParams.Add("ISOFileName", "'$F5ISOFile'")

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.text { value ''Onboarding with PowerShell in progress... [saving config]'' }"
tmsh -c "save sys config partitions all"

tmsh -c "modify sys db ui.advisory.text { value ''Onboarding with PowerShell in progress... [installing ISO, SSHD stopped]'' }"
tmsh -c "stop sys service sshd"
tmsh -c "install sys software image ''$ISOFileName'' volume HD1.2 create-volume reboot"

percentInstall=0
while true; do
    percentInstall=$(tmsh -c "show sys software status" | grep ''HD1.2'' | tr -s "\t\n " " " | cut -d " " -f 7)
    tmsh -c "modify sys db ui.advisory.text { value ''Onboarding with PowerShell in progress... [installing ISO, completed ${percentInstall}%, SSHD stopped, will reboot]'' }"
    sleep 10
done
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat config,provision

###
### after reboot, because installed from ISO:
### - SSH user/pass: root/default
### - WEBUI user/pass: admin/admin (or the same as root if root pass has been changed via SSH)
###

# Step 2
# - v14 preparation: setting passwords, disk extension, licensing, provisioning

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$F5ScriptParams.Add("F5adminPass", "'$F5VMPassPlain'")

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.color { value orange }"
tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress...'' }"
tmsh -c "modify sys db ui.advisory.enabled { value true }"
tmsh -c "modify sys global-settings gui-setup disabled"

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [setting admin and root passwords]'' }"
tmsh -c "modify auth user admin password ''$F5adminPass''"
echo -e "${F5adminPass}\n${F5adminPass}" | passwd root >/dev/null 2>&1
# tmsh -c "modify sys db systemauth.disablerootlogin value true"

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [extending disks and reboot]'' }"
tmsh -c "modify sys disk directory /appdata new-size 33554432"
tmsh -c "modify sys disk directory /var/log new-size 12288000"
tmsh -c "modify sys disk directory /var new-size 9437184"
tmsh -c "modify sys disk directory /config new-size 4546560"
tmsh -c "modify sys disk directory /shared new-size 31457280"
tmsh -c "save sys config partitions all"
tmsh -c "stop sys service sshd"
reboot
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat config,provision

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$F5ScriptParams.Add("RegistrationKey", $RegistrationKey)
$F5ScriptParams.Add("AddonRegistrationKeys", [system.String]::Join(",", $AddonRegistrationKeys))

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [modules provisioning: LTM]'' }"
tmsh -c "modify sys db provision.extramb { value 500 }"
wait_bigip_ready_provision
wait_bigip_ready_config

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [licensing]'' }"
tmsh -c "save sys config partitions all"
if [ -n "$AddonRegistrationKeys" ]; then
    /usr/local/bin/SOAPLicenseClient --basekey "$RegistrationKey" --addkey "$AddonRegistrationKeys"
    # AddonRegistrationKeysSpaceSeparated=$(echo $AddonRegistrationKeys | tr -s "," " ")
    # tmsh -c "install /sys license registration-key $RegistrationKey add-on-keys { $AddonRegistrationKeysSpaceSeparated }"    
else
    /usr/local/bin/SOAPLicenseClient --basekey "$RegistrationKey"
    # tmsh -c "install /sys license registration-key $RegistrationKey"
fi
wait_bigip_ready_license
wait_bigip_ready_config
wait_bigip_ready_provision
while ! getPromptStatus | grep -q ''Active''; do sleep 10; done;
tmsh -c "save sys config partitions all"

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [modules provisioning: APM,AFM,ASM,AVR]'' }"
tmsh -c "modify sys provision apm afm asm avr { level nominal }"
wait_bigip_ready_license
wait_bigip_ready_config
wait_bigip_ready_provision
while ! getPromptStatus | grep -q ''Active''; do sleep 10; done;

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [rebooting, SSHD stopped]'' }"
tmsh -c "save sys config partitions all"
tmsh -c "stop sys service sshd"
reboot
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat all

# Step 3
# - upload UCS and reboot

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.text { value  ''Upload UCS and restore config manually. PowerShell onboarding script has been stopped.'' }"
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat all

Write-Host -ForegroundColor Cyan "Upload UCS and restore config manually. `
Use the following command to restore configuration from UCS:`
tmsh -c ""load /sys ucs <path/to/UCS> no-license""`
`
When done, press Y and [ENTER] to continue."
$AskIfContinue = Read-Host

if ($AskIfContinue -ne "Y") {
    exit
}

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.color { value orange }"
tmsh -c "modify sys db ui.advisory.enabled { value true }"
tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [rebooting, SSHD stopped]'' }"
tmsh -c "save sys config partitions all"
tmsh -c "stop sys service sshd"
reboot
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat all

# Step 4
# - deprovision modules, leave LTM and APM only, reboot
# - re-license, backup to a UCS file, reboot

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [modules deprovisioning: AFM,ASM,AVR]'' }"
tmsh -c "modify sys provision afm asm avr { level none }"
wait_bigip_ready_provision
wait_bigip_ready_config
wait_bigip_ready_license
while ! getPromptStatus | grep -q ''Active\|REBOOT REQUIRED''; do sleep 10; done;

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [rebooting, SSHD stopped]'' }"
tmsh -c "save sys config partitions all"
tmsh -c "stop sys service sshd"
reboot
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat all

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$F5ScriptParams.Add("RegistrationKey", $NewRegistrationKey)
$F5ScriptParams.Add("AddonRegistrationKeys", [system.String]::Join(",", $NewAddonRegistrationKeys))

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [re-licensing]'' }"
tmsh -c "save sys config partitions all"
echo "Y" | tmsh -c "revoke /sys license"
wait_bigip_ready_provision
wait_bigip_ready_config
wait_bigip_ready_license
tmsh -c "save sys config partitions all"
if [ -n "$AddonRegistrationKeys" ]; then
    /usr/local/bin/SOAPLicenseClient --basekey "$RegistrationKey" --addkey "$AddonRegistrationKeys"
    # AddonRegistrationKeysSpaceSeparated=$(echo $AddonRegistrationKeys | tr -s "," " ")
    # tmsh -c "install /sys license registration-key $RegistrationKey add-on-keys { $AddonRegistrationKeysSpaceSeparated }"    
else
    /usr/local/bin/SOAPLicenseClient --basekey "$RegistrationKey"
    # tmsh -c "install /sys license registration-key $RegistrationKey"
fi
wait_bigip_ready_license
wait_bigip_ready_config
wait_bigip_ready_provision
while ! getPromptStatus | grep -q ''Active''; do sleep 10; done;
tmsh -c "save sys config partitions all"

BackupUCSFile="/shared/tmp/$(echo $HOSTNAME | cut -d ''.'' -f 1)-$(date +%Y%m%d_%H%M)-v14.1"
tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [creating unencrypted UCS: ${BackupUCSFile}]'' }"
tmsh -c "save sys ucs ${BackupUCSFile}"

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [rebooting, SSHD stopped]'' }"
tmsh -c "save sys config partitions all"
tmsh -c "stop sys service sshd"
reboot
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat all

# Step 5
# - copy config to v16 partition
# - reboot to v16
# - disable banner
# - save configuration
# - create UCS

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [copying configuration to: HD1.1]'' }"
cpcfg --source=HD1.2 HD1.1
while ! getPromptStatus | grep -q ''Active''; do sleep 10; done;

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell in progress... [rebooting to HD1.1, SSHD stopped]'' }"
tmsh -c "save sys config partitions all"
tmsh -c "stop sys service sshd"
tmsh -c "reboot volume HD1.1"
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat all

$ScriptString=''
[hashtable]$F5ScriptParams = @{}

$ScriptString = '#!/bin/bash

. /etc/bashrc
. /usr/lib/bigstart/bigip-ready-functions

tmsh -c "modify sys db ui.advisory.text { value  ''Onboarding with PowerShell has been completed.'' }"
tmsh -c "modify sys db ui.advisory.enabled { value false }"

tmsh -c "save sys config partitions all"
BackupUCSFile="/shared/tmp/$(echo $HOSTNAME | cut -d ''.'' -f 1)-$(date +%Y%m%d_%H%M)-v16.1"
tmsh -c "save sys ucs ${BackupUCSFile}"
'

$RunCommandOutput = Invoke-AzVMRunCommand -VM $F5VM -CommandId 'RunShellScript' -ScriptString $ScriptString -Parameter $F5ScriptParams

$F5ReadyOutput = Wait-F5Ready -F5VMNames $F5VMName -ResourceGroupName $ResourceGroupName -ForWhat all

Write-Host -ForegroundColor Cyan "Use Configuration Utility. Go to:`
System -> Software Management -> Antivirus Check Updates -> Package Status`
Delete all packages not marked as a System Package.
"

#endregion

#region TRANSCRIPT STOP

$F5ReadyOutput | Out-Null

Stop-Transcript

#endregion

exit

<#
END NOTES
#>
