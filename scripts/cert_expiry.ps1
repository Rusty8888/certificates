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

function Format-SafeCertNameReplace {
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$false)]
        [String]$certName,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false)]
        [String]$fromChar,
        [Parameter(Mandatory=$true, ValueFromPipeline=$false)]
        [String]$toChar
    )

    if ( $certName.Split($fromChar).Length -ge 3 ) {

        $first_char = $certName.IndexOf($fromChar)
        $last_char = $certName.LastIndexOf($fromChar)
        
        [char[]]$certNameCharArray = $certName
        
        $certNameCharArray[$first_char] = $toChar
        $certNameCharArray[$last_char] = $toChar
        
        return [string]::new($certNameCharArray)
    }
    
    return ""
}


# Main vars
$keyvaultName = "delinian-certificates"
$storageAccountName = "deliniancsr"
$containerName = "csr"
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $csrSAccKey

function main {
    # Check the certificates from Azure KeyVault
    $certificates = Get-AzKeyVaultCertificate -VaultName $keyvaultName
    $expiringCerts = @()
    $certList = @()

    foreach($cert in $certificates) {
        if($cert.Expires -lt (Get-Date).AddDays(21)) {
            $AZCert = Get-AzKeyVaultCertificate -VaultName $keyvaultName -Name $cert.Name
            $certName = $AZCert.Certificate.SubjectName.Name -split "CN="
            $certName = $certName.Replace('*',"wc")
            $certName = $certName[1]
            $e = [pscustomobject]@{
                KV_Cert_Name    = $cert.Name
                Cert_Name       = $certName
                End_Date        = Get-Date $($cert.Expires) -Format "dd-MM-yyyy HH:mm"
            }
            $expiringCerts += $e
        }
    }
    foreach($cert in $expiringCerts) {
        # Check to see if csr exists so multiple emails are not sent
        try {
            Get-AzStorageBlob -Container $containerName -Blob  "$($cert.Cert_Name).csr" -Context $context -ErrorAction Stop | Out-Null
            Write-Output "$($cert.Cert_Name) already has a renewal email"
        } catch {
            # Generate csr
            Set-CSR -CertName $($cert.Cert_Name)
            $certList += $cert
        }
    }
    # Create txt file for workflow
    $txtPath = "./csr/certlist.json"
    if (Test-Path $txtPath) { Remove-Item $txtPath -force }
    if($certList) {
        $certList
        ($certList | ConvertTo-Json) | Out-File -FilePath $txtPath -Force
    } else {
        Write-Output "There are no new cert renewals"
    }
}

function Set-CSR {
    param($CertName)
    
    Write-Host "Creating Certificate Request(CSR) for $CertName"

    $wcCheck = $CertName.Substring(0,(($CertName.IndexOf("."))))
    switch($wcCheck) {
        wc{
            $FriendlyCertName = $CertName
            $CertName = $CertName.Replace("wc","*")
            $SANs = $CertName + "," + ($CertName.Substring(($CertName.IndexOf("."))+1))
        }
        *{
            $FriendlyCertName = $CertName.Replace("*","wc")
            $SANs = $CertName + "," + ($CertName.Substring(($CertName.IndexOf("."))+1))
        }
        wildcard{
            $FriendlyCertName = $CertName.Replace("wildcard","wc")
            $CertName = $CertName.Replace("wildcard","*")
            $SANs = $CertName + "," + ($CertName.Substring(($CertName.IndexOf("."))+1))
        }
        Default {
            $FriendlyCertName = $CertName
            if(!$SANs){
                $SANs = $CertName
            }
        }
    }
    $sansArray = $SANs.Split(',')

    $CSRPath = "./csr/$FriendlyCertName.csr"
    $INFPath = "./csr/$FriendlyCertName.txt"
    $KEYPath = "./csr/$FriendlyCertName.key"
    if (Test-Path $CSRPath) { Remove-Item $CSRPath -force }
    if (Test-Path $INFPath) { Remove-Item $INFPath -force }

$request = @"
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn


[ dn ]
C = GB
ST = London
L = London
O = DELINIAN LIMITED
OU = IT
CN = $CertName

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]

"@
    $i = 1
    foreach($sanItem in $sansArray) {
        $request += "DNS.$i = $sanItem `n"
        $i ++
    }

    if(!(Test-Path "./csr")) {
        New-Item -ItemType Directory -Path "./csr" -Force | Out-Null
    }

    $request | out-file -filepath $INFPath -force -Encoding utf8
    $MyFile = Get-Content $INFPath
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($INFPath, $MyFile, $Utf8NoBomEncoding)

    openssl req -new -nodes -out $CSRPath -newkey rsa:2048 -keyout $KEYPath -config $INFPath

    # Sync the CSR to the storage account
    Set-AzStorageBlobContent -File "./csr/$FriendlyCertName.csr" -Container $containerName -Blob "$FriendlyCertName.csr" -Context $context -Force | Out-Null
    Set-AzStorageBlobContent -File "./csr/$FriendlyCertName.key" -Container $containerName -Blob "$FriendlyCertName.key" -Context $context -Force | Out-Null
    Set-AzStorageBlobContent -File "./csr/$FriendlyCertName.key" -Container "key" -Blob "$FriendlyCertName.key" -Context $context -Force | Out-Null
}
. main