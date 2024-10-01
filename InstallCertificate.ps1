
# Variables

# Certificate password.
$certPass = 'changeme'

# Domains.
$certDomains = @(inundation.ca, www.inundation.ca)

# Email Let's Encrypt will notify when close to expiration.
$notifyEmail = 'notify@inundation.ca'

# Dot source functions.
. "$PSScriptRoot\Functions.ps1"

# Request a new certificate.
$certParams = @{
    Domain = $certDomains
    PfxPass = $certPass
    AcceptTOS = $true
    Install = $true
    Contact = $notifyEmail  # optional
    Verbose = $true         # optional
}

New-PACertificate @certParams

# If Remote Desktop Services is installed, install certificate.
if (Get-WindowsFeature -Name RDS-RD-Server) {
    Install-RDSCertificate
}

# If Work Folders is installed, restart service.
if (Get-WindowsFeature -Name FS-SyncShareService) {
    Install-WFCertificate
}

# Install/update scheduled task to auto-renew certificate.
$taskname = "Renew LE Certificates"
$taskdesc = "Renews the Let's Encrypt certificate installed on this server."
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -File $PSScriptRoot\RenewCertificate.ps1"
$trigger =  New-ScheduledTaskTrigger -Daily -At 2am -RandomDelay (New-TimeSpan -Minutes 30)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask $taskname -Action $action -Trigger $trigger -User 'System' -Settings $settings -Desc $taskdesc`