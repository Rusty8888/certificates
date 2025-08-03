param($csrSAccKey)

# Import the required modules
$modules = @("Az.Accounts","Az.Storage","Az.KeyVault")
foreach($module in $modules) {
    try {
        Get-InstalledModule -Name $module -ErrorAction Stop | Out-Null
    } catch {
        Find-Module -Name $module | Install-Module -Force
    } finally {
        Import-Module $module
    }
}

# Main vars
$keyvaultName = "delinian-certificates"
$storageAccountName = "deliniancsr"
$containerName = "csr"
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $csrSAccKey

# Check the certificates in Azure KeyVault
$certificates = Get-AzKeyVaultCertificate -VaultName $keyvaultName
$expiredCerts = @()

foreach($cert in $certificates) {
    if($cert.Expires -lt (Get-Date).AddDays(-14)) {
        $AZCert = Get-AzKeyVaultCertificate -VaultName $keyvaultName -Name $cert.Name
        $certName = $AZCert.Certificate.SubjectName.Name -split "CN="
        $certName = $certName.Replace('*',"wc")
        $certName = $certName[1]
        $e = [pscustomobject]@{
            KV_Cert_Name    = $cert.Name
            Cert_Name       = $certName
            End_Date        = Get-Date $($cert.Expires) -Format "dd-MM-yyyy HH:mm"
        }
        $expiredCerts += $e
    }
}

if($expiredCerts) {
    Write-Output "Expired certs:"
    $expiredCerts

    foreach($cert in $expiredCerts) {
        $FriendlyCertName = $cert.Cert_Name
        # Check to see if csr exists so storage can be cleared down
        try {
            Get-AzStorageBlob -Container $containerName -Blob  "$FriendlyCertName.csr" -Context $context -ErrorAction Stop | Out-Null
            # Remove the cert files from the csr storage account
            Remove-AzStorageBlob -Container $containerName -Blob "$FriendlyCertName.csr" -Context $context
            Remove-AzStorageBlob -Container $containerName -Blob "$FriendlyCertName.key" -Context $context
        } catch {
            Write-Output "The cert $FriendlyCertName does not have a csr or key in the storage account"
            Continue
        }
        Remove-AzKeyVaultCertificate -VaultName $keyvaultName -Name $cert.KV_Cert_Name -Force
    }
} else {
    Write-Output "There are no expired certs in Azure key vault"
}
