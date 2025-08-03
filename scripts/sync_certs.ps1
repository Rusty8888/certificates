param($certPW,$octAPI)

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

## MAIN VARS
$holdingDir = "./certs"
$Password = ConvertTo-SecureString -String $certPW -AsPlainText -Force
# Azure KeyVault
$keyvaultName = "delinian-certificates"
# Octopus
$octopusURL = "https://octopus.delinian.com/"
$header = @{ "X-Octopus-ApiKey" = $octAPI }
$spaceid = "Spaces-1"


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
    if(Test-Path -Path $holdingDir) {
        Remove-Item -Recurse -Force $holdingDir
    }
    New-Item -ItemType Directory -Path $holdingDir -Force | Out-Null

    # Get certs using Octopus API
    $certList = Invoke-RestMethod -Method Get -Uri "$octopusURL/api/$spaceid/certificates/all" -Headers $header
    $certList = $certList | Where-Object{$null -eq $_.Archived}

    Get-OctCertificates
    Sync-DelinianCerts
}

## GET THE PFX FILES FROM OCTOPUS
function Get-OctCertificates {
    foreach($cert in $certList) {
        $filePath = "$holdingDir/$($cert.Name).pfx"
        #Write-Output "Exporting $($cert.Name)..."
        Invoke-RestMethod -Method Get -Uri "$octopusURL/$($cert.Links.Self)/export?format=Pkcs12&password=$certPW&includePrivateKey=true" -OutFile $filePath -Headers $header
    }
}

function Copy-NewCertToOctopus {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$false)]
        [String]$certName
    )
    $certType = $certName.Substring(0,3)
    if ( -not (($certType -eq "wc-") -or ($certType -eq "www") -or ($certType -eq "san"))) {
        return
    }
        
    # format for json payload from : https://octopus.com/docs/octopus-rest-api/examples/certificates/create-certificate

    # Get cert from Azure Key Vault
    $CertBase64 = Get-AzKeyVaultSecret -VaultName $keyvaultName -Name $certName -AsPlainText
    $CertBytes = [Convert]::FromBase64String($CertBase64)
    Set-Content -Path "$holdingDir/$($certName).pfx" -Value $CertBytes -AsByteStream -Force
    
    # Certificate details
    $certificateFilePath = "$holdingDir/$($certName).pfx"

    # Oh no, do something horrible to fix the pfx password
    # and by horrible, we actually deconstruct the PFX and then reconstruct it with the correct password for all parts.
    openssl pkcs12 -in $certificateFilePath -password pass: -passout pass:$certPW -nocerts -out "$holdingDir/$($certName).key"
    openssl rsa -in "$holdingDir/$($certName).key" -out "$holdingDir/$($certName).decrypted.key" -passin pass:$certPW
    openssl pkcs12 -in $certificateFilePath -passin pass: -nokeys -out "$holdingDir/$($certName).crt"
    openssl pkcs12 -out "$holdingDir/$($certName).fixedpass.pfx" -export -password pass:$certPW -in "$holdingDir/$($certName).crt" -inkey "$holdingDir/$($certName).decrypted.key"
    
    # Convert PFX file to base64
    $certificateContent = [Convert]::ToBase64String((Get-Content -Path "$holdingDir/$($certName).fixedpass.pfx" -AsByteStream))

    # Create JSON payload
    $jsonPayload = @{
        Name = $certName
        Notes = "Imported from Keyvault"
        certificateData = @{
            HasValue = $true
            NewValue = $certificateContent
        }
        password = @{
            HasValue = $true
            NewValue = $certPW
        }
        EnvironmentIds = @()
        TenantIds = @()
        TenantTags = @()
        TenantedDeploymentParticipation = "untenanted"
    }
    # Submit request
    Write-Output "Pushing $($certName) to Octopus"
    Write-Output ($jsonPayload | ConvertTo-Json -Depth 10)
    Invoke-RestMethod -Method Post -Uri "$octopusURL/api/$spaceid/certificates" -Body ($jsonPayload | ConvertTo-Json -Depth 10) -Headers $header
    

}

function Sync-DelinianCerts {
    $syncCerts = @()
    $errorCerts = @()
    $expiredCerts = @()
    $pfxCert = @()

    # Check the certificates from Octopus
    $certs = Get-ChildItem $holdingDir
    foreach($cert in $certs) {
        $pfxPath = "$holdingDir\$($cert.Name)"
        try {
            $pfxCert = Get-PfxCertificate -FilePath $pfxPath -Password $Password -ErrorAction Stop
            $pfxEndDate = (Get-Date($pfxCert.NotAfter)).ToUniversalTime()
        } catch {
            $errorCerts += $cert.Name
            continue
        }
        if($pfxEndDate -lt ((Get-Date).ToUniversalTime())) {
            $e = [pscustomobject]@{
                Cert_Name   = $cert.Name
                End_Date    = Get-Date($pfxEndDate) -Format "dd-MM-yyyy HH:mm"
            }
            $expiredCerts += $e
            continue
        } else {
            $certName = $cert.Name -split ".pfx"
            $certName = $certName[0].replace(".","-")
            $certName = $certName.replace(" ","-")
            $certName = $certName.replace("_","-")
            $c = [pscustomobject]@{
                Cert_Name   = $cert.Name
                KV_Name     = $certName
                End_Date    = $pfxEndDate
            }
            #$c
            $syncCerts += $c
        }
    }
    #$syncCerts

    $certificates = Get-AzKeyVaultCertificate -VaultName $keyvaultName
    # <= : in Octopus but not in Key Vault
    # => : in Key Vault but not in Octopus

    $certCompare = Compare-Object -ReferenceObject $syncCerts.KV_Name -DifferenceObject $certificates.Name -IncludeEqual
    $octNotkv = @()
    $kvNotoct = @()
    $OOSync = @()
    $AZSync = @()
    foreach($cer in $certCompare) {
        switch($cer.SideIndicator) {
            "<=" {
                $octNotkv += $syncCerts | Where-Object { $_.KV_Name -eq $cer.InputObject }
            }
            "=>" {
                $kvNotoct += $cer.InputObject
            }
            "==" {
                $oct = $certificates | Select-Object -Property Name,Expires | Where-Object { $_.Name -eq $cer.InputObject }
                $kv = $syncCerts | Where-Object { $_.KV_Name -eq $cer.InputObject }
                if(((Get-Date($($oct.Expires))).ToUniversalTime() -lt $kv.End_Date)) {
                    $o = [pscustomobject]@{
                        Cert_Name       = $cer.InputObject
                        Octopus_Date    = Get-Date($($oct.Expires)) -Format "dd-MM-yyyy HH:mm"
                        Azure_Date      = Get-Date($kv.End_Date) -Format "dd-MM-yyyy HH:mm"
                    }
                    $OOSync += $o
                }
                if(((Get-Date($($oct.Expires))).ToUniversalTime() -gt $kv.End_Date)) {
                    $o = [pscustomobject]@{
                        Cert_Name       = $cer.InputObject
                        Octopus_Date    = Get-Date($($oct.Expires)) -Format "dd-MM-yyyy HH:mm"
                        Azure_Date      = Get-Date($kv.End_Date) -Format "dd-MM-yyyy HH:mm"
                    }
                    $AZSync += $o
                }
            }
        }
    }
    #$certCompare

    if($errorCerts) {
        Write-Output "Certs with errors"
        Write-Output "-----------------"
        $errorCerts
        Write-Output " "
    }
    if($expiredCerts) {
        Write-Output "Octopus SA Expired certs"
        Write-Output "------------------------"
        $expiredCerts
        Write-Output " "
    }
    if($octNotkv) {
        Write-Output "In Octopus but not in Azure KeyVault"
        Write-Output "------------------------------------"
        $octNotkv
        Write-Output " "
        foreach($ob in $octNotkv) {
            $importCert = $syncCerts | Where-Object { $_.Cert_Name -eq $ob.Cert_Name }
            try {
                Import-AzKeyVaultCertificate -VaultName $keyvaultName -Name $([string]$importCert.KV_Name) -FilePath "./certs/$($importCert.Cert_Name)" -Password $Password -ErrorVariable Message -ErrorAction Stop
            } catch {
                if($Message -match "Pending Certificate not found") {
                    Write-Output "Cert that is being imported is not using standard password"
                    Write-Output "Please import this cert manually into Azure KeyVault"
                    Write-Output "Please use this name: $($importCert.KV_Name)"
                    Write-Output " "
                } else {
                    Write-Output $Message
                }
            }
            
        }
    }
    if($kvNotoct) {
        Write-Output "In Azure KeyVault but not in Octopus"
        Write-Output "------------------------------------"
        $kvNotoct
        Write-Output " "
        foreach($pushCert in $kvNotoct) {
            Copy-NewCertToOctopus -certName $pushCert
        }
    }
    if($OOSync) {
        Write-Output "Syncing certificates oct -> kv"
        Write-Output "------------------------------"
        foreach($ob in $OOSync) {
            Write-Output "Importing: $($ob.Cert_Name)"
            $importCert = $syncCerts | Where-Object { $_.KV_Name -eq $ob.Cert_Name }
            Import-AzKeyVaultCertificate -VaultName $keyvaultName -Name $([string]$importCert.KV_Name) -FilePath "./certs/$($importCert.Cert_Name)" -Password $Password
        }
    }
    if($AZSync) {
        Write-Output "Syncing certificates kv -> oct"
        Write-Output "------------------------------"
        # Octopus API cert import from Key Vault
        foreach($ob in $AZSync) {
            $importCert = $syncCerts | Where-Object { $_.KV_Name -eq $ob.Cert_Name }
            $octName = $importCert.Cert_Name -split ".pfx"
            $octName = $octName[0]

            # Get existing Octopus certificate
            [string]$certificateId = $certList | Where-Object { $_.Name -match $octName } | Select-Object -ExpandProperty Id

            # Get cert from Azure Key Vault
            $CertBase64 = Get-AzKeyVaultSecret -VaultName $keyvaultName -Name $importCert.KV_Name -AsPlainText
            $CertBytes = [Convert]::FromBase64String($CertBase64)
            Set-Content -Path "$holdingDir/$($importCert.KV_Name).pfx" -Value $CertBytes -AsByteStream -Force
            
            # Certificate details
            $certificateFilePath = "$holdingDir/$($importCert.KV_Name).pfx"

            # Convert PFX file to base64
            $certificateContent = [Convert]::ToBase64String((Get-Content -Path $certificateFilePath -AsByteStream))

            # Create JSON payload
            $jsonPayload = @{
                certificateData = $certificateContent
            }

            # Submit request
            Write-Output "Replacing $octName in Octopus"
            Invoke-RestMethod -Method Post -Uri "$octopusURL/api/$spaceid/certificates/$certificateId/replace" -Body ($jsonPayload | ConvertTo-Json -Depth 10) -Headers $header
        }
    }
}

. main
