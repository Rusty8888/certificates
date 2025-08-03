param($csrSAccKey, $certPW)

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
$storageAccountName = "deliniancsr"
$keyvaultName = "delinian-certificates"
$shareName = "pem"

# USER NEEDS TO ADD PEM CERT FROM CSC TO THE PEM FILE SHARE

# Connecting to the pem file share
# This is for uploading the pem certs that come from csc
<#
macos:
open smb://deliniancsr:VAlq6sersWpWTpkgmGK%2FDx%2BHfgqijMcz%2FL5SO0DXYrig0Fm2vod1rxHF3ouRayrjzv5WaRNw19Dl%2BAStdPHewg%3D%3D@deliniancsr.file.core.windows.net/pem
#>

# SET UP DIRS
if (Test-Path "./csr") {
    Remove-Item -Recurse -Force "./csr"
}
New-Item -ItemType Directory -Path "./csr" -Force | Out-Null


# Get the pem from the file share
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $csrSAccKey
$pemFiles = (Get-AzStorageFile -ShareName $shareName -Context $context).Name | Where-Object { $_ -match ".pem"  -and $_ -notmatch "^._"}
if($pemFiles){
    Write-Output "Found pem files in the file share:"
    $pemFiles
    foreach($pem in $pemFiles) {
        # Get the file name without extension
        $FriendlyCertName = $pem -split ".pem"
        $FriendlyCertName = $FriendlyCertName[0]
        
        # Get the pem file from the file share
        Get-AzStorageFileContent -ShareName $shareName -Path $pem -Destination "./csr/" -Context $context -ErrorAction Stop

        # Get the key file from the storage account
        $containerName = "csr"
        $context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $csrSAccKey
        Get-AzStorageBlobContent -Container $containerName -Blob  "$FriendlyCertName.key" -Destination "./csr/" -Context $context | Out-Null
        $keyPath = "./csr/$FriendlyCertName.key"

        # Create the pfx
        $pfxPath = "./csr/$FriendlyCertName.pfx"
        $certPath = "./csr/$pem"
        openssl pkcs12 -export -out $pfxPath -inkey $keyPath -in $certPath -password pass:$certPW

        # Upload the pfx to Azure key vault
        $azCertName = $FriendlyCertName.replace('.','-')
        $Password = ConvertTo-SecureString -String $certPW -AsPlainText -Force
        # NOTE: Once key vault has uploaded the certificate it removes the password
        Import-AzKeyVaultCertificate -VaultName $keyvaultName -Name $azCertName -FilePath $pfxPath -Password $Password -ErrorAction Stop

        # Tidy up cert process
        if(Get-AzKeyVaultCertificate -VaultName $keyvaultName -Name $azCertName) {
            # Remove the pem from the file share
            Remove-AzStorageFile -ShareName $shareName -Path $pem -Context $context
            Remove-AzStorageFile -ShareName $shareName -Path "._$pem" -Context $context -ErrorAction SilentlyContinue
        
            # Remove the cert files from the csr storage account
            Remove-AzStorageBlob -Container $containerName -Blob "$FriendlyCertName.csr" -Context $context
            Remove-AzStorageBlob -Container $containerName -Blob "$FriendlyCertName.key" -Context $context
        } else {
            Write-Output "The cert $azCertName does not seem to have made it to Azure keyvault"
            Write-Output "The csr and key ($FriendlyCertName) are still present on the certificate/csr storage account"
        }
    }
} else {
    Write-Output "There are no pem files in the file share to complete"
}