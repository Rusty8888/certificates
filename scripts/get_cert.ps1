param($certName, $certPwd, $win2016)

$keyvaultName = "delinian-certificates"
$certPath = "./certs/downloads"
$holdingDir = "./certs"

if(Test-Path $holdingDir) { Remove-Item $holdingDir -Recurse -force }
New-Item -ItemType Directory -Path $holdingDir -Force | Out-Null
New-Item -ItemType Directory -Path $certPath -Force | Out-Null

<#
# This is to complete a cert from the backup key and pem storage account containers
# It was created before the solution to using the key vault pfx cert was found
# It has been left here should it ever need to be implemented
function Complete-Cert {
    # vars for this function
    $storageAccountName = "deliniancsr"
    $context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $csrSAccKey
    
    # Get the pem and key file from the storage account
    Get-AzStorageBlobContent -Container "key" -Blob  "$certName.key" -Destination $holdingDir -Context $context | Out-Null
    Get-AzStorageBlobContent -Container "pem" -Blob  "$certName.pem" -Destination $holdingDir -Context $context | Out-Null

    # Use openssl to create the pfx with a password
    openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -nomac -out "$certPath/$certName.pfx" -inkey "$holdingDir/$certName.key" -in "$holdingDir/$certName.pem" -password pass:$certPwd
}
#>

$certificates = Get-AzKeyVaultCertificate -VaultName $keyvaultName | Where-Object { $_.Name -match $certName }
if($certificates) {
    foreach($cert in $certificates) {
        $fullCertPath = "$holdingDir/$($cert.Name).pfx"
        
        # Get cert from Azure Key Vault
        $pfxSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $cert.Name -AsPlainText
        $certBytes = [Convert]::FromBase64String($pfxSecret)
        Set-Content -Path $fullCertPath -Value $certBytes -AsByteStream

        ## The following is two methods for reconstructing the certificate with a password
        # FOR WINDOWS SERVER 2016 OR EARLIER AN OLDER ENCRYPTION METHOD IS NEEDED
        # The Win2016 cert does not always work when needed elsewhere, so this is a workaround
        # For Windows Server 2019 (and elsewhere) and later, the default encryption method is sufficient
        if($win2016 -eq $true) {
            # Add password to pfx cert (key vault removes it once stored)
            Write-Output "Win 2016 compatible cert"
            openssl pkcs12 -in $fullCertPath -passin pass:"" -out "$holdingDir/$($cert.Name).pem" -nodes
            openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -nomac -in "$holdingDir/$($cert.Name).pem" -passin pass:$certPwd -out "$certPath/$($cert.Name).pfx" -passout pass:$certPwd
        } else {
            # Deconstruct the PFX and then reconstruct it with the password for all parts
            Write-Output "Standard cert download"
            $cert_name = $cert.Name
            openssl pkcs12 -in $fullCertPath -passin pass:"" -nocerts -out "$holdingDir/$($cert_name).key" -nodes
            openssl rsa -in "$holdingDir/$($cert_name).key" -passin pass:$certPwd -out "$holdingDir/$($cert_name).decrypted.key" 
            openssl pkcs12 -in $fullCertPath -passin pass:"" -nokeys -out "$holdingDir/$($cert_name).crt"
            openssl pkcs12 -out "$certPath/$($cert.Name).pfx" -export -passout pass:$certPwd -in "$holdingDir/$($cert_name).crt" -inkey "$holdingDir/$($cert_name).decrypted.key"
        }

        if(Test-Path -Path $fullCertPath) {
            Write-Output "Certificate $($cert.Name) downloaded"
        } else {
            throw "$($cert.Name) download failed"
        }
    }
} else {
    throw "No certificate found with name $certName"
}