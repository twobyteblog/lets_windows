
<#
.SYNOPSIS
  Requests and installs a Let's Encrypt certificate on a Windows-based host. Includes creating a scheduled task for auto-renewing the certificate as required.

.NOTES
  Version:        1.0
  Author:         twobyte.blog
  Creation Date:  November 01, 2024
  
.EXAMPLE
  .\Certificate.ps1 (Generates and installs new certificate.)
  .\Certificate.ps1 -Renew  (Renews existing certificate.)
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

param (
    [switch]$Renew
)

#Set Error Action to Stop
$ErrorActionPreference = "Stop"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# CloudFlare Token for Domain Control Validation (DCV).
$cloudflareToken = ''

# Certificate password.
$certPass = 'changeme'

# Domain(s). If using hostname, you can automate using "$([System.Net.Dns]::GetHostEntry([string]"localhost").HostName)".
$hostname = $([System.Net.Dns]::GetHostEntry([string]"localhost").HostName)
$certDomains = @($hostname, twobyte.blog, twobyte.ca)

# Contact email address, for 
$notifyEmail = 'alerts@twobyte.blog'

#-----------------------------------------------------------[Functions]------------------------------------------------------------

# Exports certificate into Base64 format.

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

# Installs/refreshes the certificate for Remote Desktop Services. Includes refreshing the certificate for the RDS Web Client.

function Install-RDSCertificate {

    Import-Module RemoteDesktopServices

    $PrimaryDomain = "$([System.Net.Dns]::GetHostEntry([string]"localhost").HostName)"
    Write-Host "Primary Domain: $PrimaryDomain"

    $RDSRoles = @{
        "RDGateway"     =   "RDS-Gateway"
        "RDRedirector"  =   "RDS-Connection-Broker"
        "RDPublishing"  =   "RDS-RD-Server"
        "RDWebAccess"   =   "RDS-Web-Access"
    }

    $NewCert = Get-PACertificate $PrimaryDomain -ErrorAction Stop

    foreach ($Role in $RDSRoles.Keys) {

        $ServiceName = $RDSRoles[$Role]

        if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq $ServiceName }) {

            Set-RDCertificate `
            -Role $Role `
            -ImportPath $NewCert.PfxFile `
            -Password $NewCert.PfxPass `
            -ConnectionBroker $PrimaryDomain `
            -Force `
            -ErrorAction Stop

            Write-Host "Installed Certificate for $Role."
        } else {
            Write-Host "$Role not found, skipping."
        }
    }

    if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq "RDS-Web-Access" } ){

        $Base64Cert = "$PSScriptRoot\Base64Cert.cer"

        if (Test-Path $Base64Cert) {
            Remove-Item -Path $Base64Cert
            }

        # Export certificate as base64.
        $ExportCert = Get-ChildItem -Path "Cert:\LocalMachine\My\$($NewCert.Thumbprint)"
        Export-Base64Certificate -Cert $ExportCert -FilePath $Base64Cert | Out-Null

        # Import certificate.
        Import-RDWebClientBrokerCert $Base64Cert
        Publish-RDWebClientPackage -Type Production -Latest
    }

}

# Installs/refreshes the certificate for Work Folders.

function Install-WFCertificate{

    # Collect certificate thumbprint.
    $NewCert = Get-PACertificate $PrimaryDomain -ErrorAction Stop

    # Refresh certificate installed for Work Folders.
    try {
        netsh http delete sslcert ipport=0.0.0.0:443
        netsh http add sslcert ipport:0.0.0.0:443 certhash=$($NewCert.Thumbprint) appid={CE66697B-3AA0-49D1-BDBD-A25C8359FD5D} certstorename=MY
    } catch {
        Write-Error "Failed to successfully apply new Work Folders certificate."
    }

    # Restart Work Folders service.
    Restart-Service -Name FS-SyncShareService

}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

if ($Renew) {

  $hostname = @([System.Net.Dns]::GetHostEntry([string]"localhost").HostName)

  $oldCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$hostname" } | Sort-Object -Descending NotAfter | Select-Object -First 1

  if (Submit-Renewal -Verbose) {

      # Remove replaced certificate.
      $oldCert | Remove-Item

      # If Remote Desktop Services is installed, install certificate.
      if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq "RDS-RD-Server" } ) {
          Install-RDSCertificate
      }

      # If Work Folders is installed, restart service.
      if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq "FS-SyncShareService" }) {
          Install-WFCertificate
      }

  }
} else {

    # If running on Windows 2016 or older, force the use of TLS 1.2.
    $OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version

    if ($OSVersion -le 10.0.20348){
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    # Install Posh-ACME.
    Install-Module -Name Posh-ACME -Scope AllUsers -Force

    # API Token for CloudFlare DCV.
    $token = ConvertTo-SecureString $cloudflareToken -AsPlainText -Force
    $pArgs = @{CFToken=$token}

    # Request a new certificate using Posh-ACME.
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
        $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-ExecutionPolicy Bypass -File C:\Scripts\lets_windows\Certificate.ps1 -Renew'
        $TaskTrigger =  New-ScheduledTaskTrigger -Daily -At 2am -RandomDelay (New-TimeSpan -Minutes 30)
        $TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

        $TaskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $TaskName}

        if ($TaskExists) {

            # Delete existing scheduled task.
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false

            # Create scheduled task.
            Register-ScheduledTask $TaskName -Action $TaskAction -Trigger $TaskTrigger -User 'System' -Settings $TaskSettings -Desc $TaskDesc
        }

        # If Remote Desktop Services is installed, update service with certificate.
        if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq "RDS-RD-Server" } ) {
            Install-RDSCertificate
        }

        # If Work Folders is installed, install certificate and restart service.
        if (Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.Name -eq "FS-SyncShareService" }) {
            Install-WFCertificate
        }
    }

}