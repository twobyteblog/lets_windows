# Functions

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
        
    ) {

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
}

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

        if (Get-WindowsFeature -Name $ServiceName) {

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

    if (Get-WindowsFeature -Name RDS-Web-Access){

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
