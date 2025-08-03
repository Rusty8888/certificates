$config_loc = "/etc/nginx/conf.d/http/servers"
$crt_config = "/etc/ssl/nginx/config_collect.json"

$aConfigs = @()
Get-ChildItem -Path $config_loc -Recurse -Include *.conf | Select-String -Pattern ".crt" | `
    foreach-object {
        $line = $_.Line
        $firstSlashIndex = $line.IndexOf('/') # Find the index of the first '/'
        $firstSemiColonIndex = $line.IndexOf(';', $firstSlashIndex) # Find the index of the first ';' after the first '/'
        $lastSlashIndex = $line.LastIndexOf('/') # Find the index of the last '/'
        $lastSemiColonIndex = $line.IndexOf(';', $lastSlashIndex) # Find the index of the first ';' after the last '/'
        
        if ($firstSlashIndex -ne -1 -and $firstSemiColonIndex -ne -1) {
            $certPath = $line.Substring($firstSlashIndex, $firstSemiColonIndex - $firstSlashIndex)
        } else {
            $certPath = "Not found"
        }

        if ($lastSlashIndex -ne -1 -and $lastSemiColonIndex -ne -1) {
            $certName = $line.Substring($lastSlashIndex + 1, $lastSemiColonIndex - $lastSlashIndex -1)
        } else {
            $certName = "Not found"
        }

        # Extract the certificate end date
        $certEndDate = ""
        if ($certPath -ne "Not found") {
            $opensslOutput = & openssl x509 -in $certPath -noout -enddate 2>$null
            if ($opensslOutput) {
                $certEndDate = $opensslOutput -replace 'notAfter=', ''
            }
        }

        $aConfigs += [PSCustomObject]@{
            Config_Path = $_.Path
            Cert_Path   = $certPath
            Cert_Name   = $certName
            Cert_End    = $certEndDate
        }
    }

$aConfigs | Format-Table -AutoSize
$aConfigs | ConvertTo-Json > $crt_config
# DATE OUTPUT: Aug 14 23:59:59 2024 GMT