<#
.SYNOPSIS
  Requests and installs a Let's Encrypt certificate on a Windows-based host. Includes creating a scheduled task for auto-renewing the certificate as required.

.NOTES
  Version:        1.0
  Author:         twobyte.blog
  
.EXAMPLE
  .\Certificate.ps1 -Install (Generates and installs new certificate.)
  .\Certificate.ps1 -Renew  (Renews existing certificate.)
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

param (
    [switch]$Renew,
    [switch]$Install
)

#Set Error Action to Stop
$ErrorActionPreference = "Stop"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# CloudFlare Token for Domain Control Validation (DCV).
$cloudflareToken = ""

# Use Let's Encrypt's staging server rather then production.
$certStaging = $false

# Certificate password.
$certPass = "changeme"

# Domain(s). If using hostname, you can automate using the $hostname variable.
$hostname = $([System.Net.Dns]::GetHostEntry([string]"localhost").HostName)
$certDomains = @($hostname, twobyte.blog, twobyte.ca)

# Contact email address, for 
$notifyEmail = "alerts@twobyte.blog"

# Posh-ACME configuration location. 
# By default, this will be a 'config' folder located aloneside the script.
$env:POSHACME_HOME = "$PSScriptRoot\config"

#-----------------------------------------------------------[Functions]------------------------------------------------------------

# Exports certificate into Base64 format.

# Function pulled from https://github.com/chelnak/ExportBase64Certificate. Written by Craig Gumbley.
function Export-Base64Certificate {

    [CmdletBinding()][OutputType('[System.IO.FileSystemInfo]')]
    Param(

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [String]$FilePath,

        [Parameter(Position=2)]
        [ValidateNotNullOrEmpty()]
        [Switch]$Raw
        
    )

    if ($PSBoundParameters.ContainsKey("Raw")) {

        $Base64Cert = [System.Convert]::ToBase64String($Cert.RawData, "None")

    } else {

        $Base64Cert = @(
            '-----BEGIN CERTIFICATE-----'
            [System.Convert]::ToBase64String($Cert.RawData, "InsertLineBreaks")
            '-----END CERTIFICATE-----'
        )

    }

    $Base64Cert | Out-File -FilePath $FilePath -Encoding ascii

}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# If running on Windows 2016 or older, force the use of TLS 1.2.
$OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version

if ($OSVersion -le "10.0.20348"){
    Write-Host "Setting .NET to use TLS 1.2."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# Install Posh-ACME.
if (-not (Get-Module -ListAvailable -Name Posh-ACME)) {
    Write-Host "Posh-ACME not detected, installing."
    Install-Module -Name Posh-ACME -Scope AllUsers -Force
}

# API Token for CloudFlare DCV.
$token = ConvertTo-SecureString $cloudflareToken -AsPlainText -Force
$pArgs = @{CFToken=$token}

# Set staging server.
if ($certStaging) {
    Write-Host "Setting Let's Encrypt to staging server."
    Set-PAServer LE_STAGE
    
} else {
    Write-Host "Setting Let's Encrypt to production server."
    Set-PAServer LE_PROD
    }

# Install certificate if -Install is specified.

if ($Install) {

    # Request a new certificate using Posh-ACME.
    Write-Host "Starting certificate signing process..."

    $certParams = @{
        Domain = $certDomains
        PfxPass = $certPass
        DnsPlugin = 'Cloudflare'
        PluginArgs = $pArgs
        AcceptTOS = $true
        Install = $true
        Contact = $notifyEmail  # optional
        Verbose = $true         # optional
    }

    if (New-PACertificate @certParams) {

        # Install/update scheduled task to auto-renew certificate.

        $TaskName = "Renew LE Certificates"
        $TaskDesc = "Renews the Let's Encrypt certificate installed on this server."
        $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -File $PSScriptRoot\Certificate.ps1 -Renew"
        $TaskTrigger =  New-ScheduledTaskTrigger -Daily -At 2am -RandomDelay (New-TimeSpan -Minutes 30)
        $TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

        # Delete any existing scheduled task.
        $TaskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $TaskName}

        if ($TaskExists) {

            Write-Host "Deleting old scheduled task for Let's Encrypt renewals."
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false | Out-Null
        }

        # Create scheduled task.
        Write-Host "Creating new scheduled task for Let's Encrypt renewals."
        Register-ScheduledTask $TaskName -Action $TaskAction -Trigger $TaskTrigger -User 'System' -Settings $TaskSettings -Desc $TaskDesc | Out-Null

    } else {
            Write-Host "Certificate already exists. Skipping."
        }
}

# Renew certificate if -Renew is specified.

if ($Renew) {

    Write-Host "Starting certificate renewal process..."

    if ( -not (Submit-Renewal -Verbose)) {
        Write-Host "Certificate OK. Renewal not required."
    }
}

# Installs/refreshes the certificate for Remote Desktop Services. Includes refreshing the certificate for the RDS Web Client.

if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq "RDS-RD-Server" } ) {

    Write-Host "RDS role installed on host, validating."

    Import-Module RemoteDesktopServices

    # Determine FQDN of host and collect Let's Encrypt certificate information.
    $PrimaryDomain = "$([System.Net.Dns]::GetHostEntry([string]"localhost").HostName)"
    Write-Host "RDS: Primary Domain is $PrimaryDomain"

    $NewCert = Get-PACertificate $PrimaryDomain -ErrorAction Stop

    # Check each role and verify that the certificate is installed/latest.
    $RDSRoles = @{
        "RDGateway"     =   "RDS-Gateway"
        "RDRedirector"  =   "RDS-Connection-Broker"
        "RDPublishing"  =   "RDS-RD-Server"
        "RDWebAccess"   =   "RDS-Web-Access"
    }

    foreach ($Role in $RDSRoles.Keys) {

        $ServiceName = $RDSRoles[$Role]

        if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq $ServiceName }) {

            $RoleCert = Get-RDCertificate -Role $Role

            if ($NewCert.Thumbprint -ne $RoleCert.Thumbprint) {

                Write-Host "RDS: Certificate thumbprints do not match for $Role. Installing new certificate."

                Set-RDCertificate `
                -Role $Role `
                -ImportPath $NewCert.PfxFile `
                -Password $NewCert.PfxPass `
                -ConnectionBroker $PrimaryDomain `
                -Force `
                -ErrorAction Stop

                Write-Host "RDS: $Role certificate successfully installed."
            } else {
                Write-Host "RDS: $Role certificate thumbprint matches, skipping."
            }

        } else {
            Write-Host "$Role not found, skipping."
        }
    }

    if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq "RDS-Web-Access" } ){

        $RoleThumbprint = Get-RDWebClientBrokerCert | Select-Object Thumbprint

        if ($NewCert.Thumbprint -ne $RoleThumbprint) {

        Write-Host "RDS: Certificate thumbprints do not match for RDS Web Access. Installing new certificate."

        $Base64Cert = "$PSScriptRoot\Base64Cert.cer"

        if (Test-Path $Base64Cert) {
            Remove-Item -Path $Base64Cert
            }

        # Export certificate as base64.
        $ExportCert = Get-ChildItem -Path "Cert:\LocalMachine\My\$($NewCert.Thumbprint)"
        Export-Base64Certificate -Cert $ExportCert -FilePath $Base64Cert | Out-Null

        # Import certificate.
        Import-RDWebClientBrokerCert $Base64Cert
        
        } else {
            Write-Host "RDS: RDS Web Access certificate thumbprint matches, skipping."
        }
    }

} else {
    Write-Host "RDS role not detected, skipping."
}

# Installs/refreshes the certificate for Work Folders.

if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq "FS-SyncShareService" }) {

    Write-Host "Work Folders role installed on host, validating."

    # Collect new certificate thumbprint.
    $NewCert = Get-PACertificate $PrimaryDomain -ErrorAction Stop

    # Collect installed certificate thumbprint.
    $Thumbprint = netsh http show sslcert | Select-String -Pattern "Certificate Hash:\s*(\S+)" | ForEach-Object { $_.Matches.Groups[1].Value }

    if ($($NewCert.Thumbprint.ToString()) -eq $Thumbprint) {

        try {
            # Refresh certificate installed for Work Folders.
            $Thumbprint = ($NewCert.Thumbprint).Replace(" ", "").Trim()
            $AppId = "{CE66697B-3AA0-49D1-BDBD-A25C8359FD5D}"

            netsh http delete sslcert ipport=0.0.0.0:443
            netsh http add sslcert ipport=0.0.0.0:443 certhash=$Thumbprint appid=$AppId certstorename=MY

            # Restart Work Folders service.
            Restart-Service -Name SyncShareSvc

        } catch {
            Write-Error "Failed to successfully apply new Work Folders certificate: $_"
        }
    }

} else {
    Write-Host "Work Folders feature not detected, skipping."
}

# Delete expired certificates.

$ToDeleteCerts = Get-ChildItem -Path Cert:\LocalMachine\My `
| Where-Object { $_.Subject -match $certDomains } `
| Sort-Object -Property NotAfter `
| Select-Object -SkipLast 1

foreach ($cert in $ToDeleteCerts) {
    Remove-Item -Path "Cert:\LocalMachine\My\$($cert.Thumbprint)"
    Write-Host "Deleted certificate: $($cert.Subject) with Thumbprint $($cert.Thumbprint)"
}