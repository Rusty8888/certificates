$crt_loc = "/etc/ssl/nginx"
$crt_config = "/etc/ssl/nginx/config_clean.txt"
$crt_delete = "/etc/ssl/nginx/crt_clean.txt"
$config_loc = "/etc/nginx/conf.d/http/servers"

function main {
    if(Test-Path -Path $crt_config){Remove-Item -Path $crt_config}
    if(Test-Path -Path $crt_delete){Remove-Item -Path $crt_delete}
    Remove-StarCerts
    Remove-OldCerts
    # Remove-EmptyDirs
    # Get-Certs
}

function Remove-StarCerts {
    $wc_crts = Get-ChildItem -Path $crt_loc/ -Recurse -Include ``*.*.crt
    if($wc_crts) {
        foreach ($crt in $wc_crts) {
            [string]$crt_path = $crt.FullName
            [string]$key_crt = ($crt.FullName) -replace "crt","key"
            Write-Output "DELETING * CERT: $($crt.Name)"
            Remove-Item -LiteralPath $crt_path
            Remove-Item -LiteralPath $key_crt
        }
    }
}

function Remove-OldCerts {
    $ErrorActionPreference = 'Stop'
    $crts = Get-ChildItem -Path $crt_loc/ -Recurse -Include *.crt
    $aCrts = @()
    $aConfigs = @()
    foreach($crt in $crts) {
        $crt_path = $crt.FullName
        $key_crt = ($crt.FullName) -replace "crt","key"
        try {
            $crt_end = openssl x509 -in "$crt_path" -noout -enddate 2>/dev/null
        } catch {
            Write-Output "CERT ERROR, DELETING: $($crt.Name)"
            Remove-Item -LiteralPath $crt_path
            Remove-Item -LiteralPath $key_crt
        }
        $crt_end = ($crt_end -split "=")[1]
        $crt_end = ($crt_end -split " G")[0]
        $crt_end = ($crt_end -split "  ")
        if($crt_end.count -gt 1) {
            $crt_end[1] = " 0" + $crt_end[1]
            $crt_end = $crt_end[0] + $crt_end[1]
        }
        try {
            $crt_end = [datetime]::parseexact($crt_end, 'MMM dd HH:mm:ss yyyy', $null)
        } catch {
            Continue
        }
        if($crt_end -lt (get-date)) {
            if(Resolve-NginxConfig -crtName $crt.Name) {
                $aConfigs += [pscustomobject]@{
                    Cert_Name   = $crt.Name
                    Cert_End    = $crt_end
                    Cert_Path   = $crt_path
                    Config      = $configName
                }
            } else {
                $aCrts += [pscustomobject]@{
                    Cert_Name   = $crt.Name
                    Cert_End    = $crt_end
                    Cert_Path   = $crt_path
                    Config      = $false
                }
                Remove-Item -LiteralPath $crt_path -ErrorAction 'SilentlyContinue'
                Remove-Item -LiteralPath $key_crt -ErrorAction 'SilentlyContinue'
            }
        }
    }
    if($aCrts){$aCrts | Format-List > $crt_delete}
    if($aConfigs){$aConfigs | Format-List > $crt_config}
}
function Resolve-NginxConfig {
    param (
        $crtName
    )
    Get-ChildItem -Path $config_loc -Recurse -Include *.conf |
    ForEach-Object {
        $config_content = Get-Content $_.FullName
        if($config_content | Select-String -Pattern $crtName) {
            $Global:configName = $_.Name
            $true
        }
    }
}
# Due to permissions, this has been moved to Ansible
function Remove-EmptyDirs {
    $dir_list = Get-ChildItem -Directory -Path $crt_loc
    foreach($dir in $dir_list) {
        if((Get-ChildItem -File -Path $dir.FullName).count -eq 0) {
            Write-Output "REMOVING EMPTY DIR: $($dir.FullName)"
            #Remove-Item -LiteralPath ($dir.FullName)
        }
    }
}

function Get-Certs {
    $dir_list = Get-ChildItem -Directory -Path $crt_loc
    foreach($dir in $dir_list) {
        $dir.Name
        $child_list = Get-ChildItem -File -Path $dir.FullName
        foreach($file in $child_list) {
            if($file.Name -match ".crt") {
                $crt_path = $file.FullName
                $crt_end = openssl x509 -in "$crt_path" -noout -enddate 2>/dev/null
                $crt_end = ($crt_end -split "=")[1]
                Write-Output "    ↳ $($file.Name)"
                Write-Output "          ↳ $crt_end"
            } else {
                Write-Output "    ↳ $($file.Name)"
            }
        }
    }
}

. main