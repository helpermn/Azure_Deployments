# Azure_Deployments

## F5_deployment

It's a PowerShell deployment of F5 Big-IP VE

You need to manually create a file:
>
    F5_deploy_secrets.ps1

And set the following variables:
>
    [string]$SubscriptionId = ""
    [string]$TenantId = ""

    [string]$HomeIP = ""

HomeIP is a source IP address to provide network access (create NSG rules) for:
- SSH (22/tcp)
- WebUI (8443/tcp)

Running script creates a log file in append mode:
>
    F5_deploy.log

New VM password will be automatically generated, displayed and put into the log file.
