
# Dot source functions.
. "$PSScriptRoot\Functions.ps1"

$hostname = @(inundation.ca)

$oldCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$hostname" } | Sort-Object -Descending NotAfter | Select-Object -First 1

if (Submit-Renewal -Verbose) {

    # Remove replaced certificate.
    $oldCert | Remove-Item

    # If Remote Desktop Services is installed, install certificate.
    if (Get-WindowsFeature -Name RDS-RD-Server) {
        Install-RDSCertificate()
    }

    # If Work Folders is installed, restart service.
    if (Get-WindowsFeature -Name FS-SyncShareService) {
        Restart-Service -Name FS-SyncShareService
    }

}

