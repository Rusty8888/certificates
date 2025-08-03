param($csrSAccKey, $certName, $SANs)

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
$containerName = "csr"
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $csrSAccKey

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


function main {
    if(Test-Path -Path "./csr") {
        Remove-Item "./csr" -Recurse -Force
    }
    New-Item -Path "./csr" -ItemType Directory | Out-Null
    Set-CSR -CertName $certName
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

    # Sync the CSR and key to the storage account
    Set-AzStorageBlobContent -File "./csr/$FriendlyCertName.csr" -Container $containerName -Blob "$FriendlyCertName.csr" -Context $context -Force | Out-Null
    Set-AzStorageBlobContent -File "./csr/$FriendlyCertName.key" -Container $containerName -Blob "$FriendlyCertName.key" -Context $context -Force | Out-Null
    Set-AzStorageBlobContent -File "./csr/$FriendlyCertName.key" -Container "key" -Blob "$FriendlyCertName.key" -Context $context -Force | Out-Null
}
. main