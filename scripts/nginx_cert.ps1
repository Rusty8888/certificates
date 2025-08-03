$keyvaultName = "delinian-certificates"
$certPath = "./certs/downloads"

function main {
    Test-NginxCerts
}

function Test-NginxCerts {
    $cert_list = Get-Content "$certPath/config_certs.json" | ConvertFrom-Json
    $check_certs = $cert_list | Select-Object Cert_Name, Cert_End -Unique
    $cert_compare = @()
    foreach($cert in $check_certs) {
        $azCertName = $cert.Cert_Name -replace '.crt', ''
        $azCertName = $azCertName -replace '[^a-zA-Z]', '-'
        $nxDate = $cert.Cert_End -replace ' GMT',''
        $nxDate = $nxDate -split " "
        if(-not ($nxDate[1] -as [int])) {
            $nxDate[1] = "0"+$nxDate[2] # Replace with 0
            $nxDate = $nxDate[0..0] + $nxDate[1..1] + $nxDate[3..($nxDate.Count - 1)] # Remove $nxDate[2]
        }
        # Reconstruct $nxDate as a string
        $nxDateString = $nxDate -join " "
        # Parse the string into a [datetime] object
        try {
            $nxDate = [datetime]::ParseExact($nxDateString, "MMM dd HH:mm:ss yyyy", $null)
            $nxDate = $nxDate.ToString("dd/MM/yyyy HH:mm:ss")
        } catch {
            throw "Error parsing date: $_"
        }
        $azCert = Get-AzKeyVaultCertificate -VaultName $keyvaultName -Name $azCertName | Select-Object Name, Expires
        $azCertEnd = ($azCert.Expires).ToString("dd/MM/yyyy HH:mm:ss")
        $cert_compare += [PSCustomObject]@{
            nxCert_Name = $cert.Cert_Name
            azCert_Name = $azCert.Name
            nxCert_End  = $nxDate
            azCert_End  = $azCertEnd
        }
    }
    $cert_ok = @()
    foreach($c in $cert_compare) {
        if($c.azCert_End -gt $c.nxCert_End) {
            Write-Output " "
            Write-Output "Updating $($c.nxCert_Name)"
            Write-Output $c | Format-Table -AutoSize
            Set-NginxCerts -cert_name $c.azCert_Name -n_cert_name $c.nxCert_Name
            Write-Output " "
        } elseif($c.nxCert_End -eq $c.azCert_End) {
            $cert_ok += $c
        } elseif($c.nxCert_End -gt $c.azCert_End) {
            throw "The Nginx certificate $($c.nxCert_Name) is newer than the one in Key Vault $($c.azCert_Name) - please check"
        } else {
            throw "Something with the date comparison went wrong!"
        }
    }
    if($cert_ok) {
        Write-Output "The following certs are up to date with those in Azure:"
        Write-Output $cert_ok | Format-Table -AutoSize
    }
    if($cert_compare.count -eq $cert_ok.count) {
        Write-Output "There are no certs that need updating in Nginx"
        $cert_ok > "$certPath/cert_ok.txt"
    }
}
function Set-NginxCerts {
    param($cert_name, $n_cert_name)
    
    #if(Test-Path $certPath) { Remove-Item $certPath -Recurse -force }
    #New-Item -ItemType Directory -Path $certPath -Force | Out-Null

    try {
        Write-Output "Retrieving $cert_name from key vault"
        $certificate = Get-AzKeyVaultCertificate -VaultName $keyvaultName -Name $cert_name -ErrorAction Stop
    } catch {
        throw "No certificate found with name $cert_name"
    }

    $cName = $certificate.Name
    Write-Output "$cName found"
    $fullCertPath = "$certPath/$cName.pfx"
    $certificateBytes = $certificate.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
    [System.IO.File]::WriteAllBytes($fullCertPath, $certificateBytes)
    $n_cert_key = $n_cert_name -replace '.crt','.key'
    openssl pkcs12 -in $certPath/$cName.pfx -nocerts -nodes -password pass:$certpwd -out $certPath/$n_cert_key
    if(Test-Path "$certPath/$n_cert_key") {
        Write-Output "key file generated successfully"
    } else {
        throw "$n_cert_key generation failed"
    }
    openssl pkcs12 -in $certPath/$cName.pfx -nokeys -nodes -password pass:$certpwd -out $certPath/$n_cert_name
    if(Test-Path "$certPath/$n_cert_name") {
        Write-Output "crt file generated successfully"
    } else {
        throw "$n_cert_name generation failed"
    }
}

function Copy-NginxCerts {
    # This can be used to copy files to servers using Powershell instead of Ansible etc
    foreach($s in $servers) {
        $sVM = "$s.emazure.internal"
        pwsh -command "(& sshpass -p $empwd scp $certPath/$nCertName.* emadmin@$($sVM):/home/emadmin/tmp)"
    }
}

. main