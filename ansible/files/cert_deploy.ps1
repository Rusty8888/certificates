$tmp_loc = "/tmp/certs/downloads"
$crt_loc = "/etc/ssl/nginx"

$dir_list = Get-ChildItem -Directory -Path $crt_loc
$cert_name = Get-ChildItem -Path $tmp_loc | Where-Object { $_.Name -match "*.crt"}


$crt_path = @()
foreach($dir in $dir_list) {
  $dir.Name
  $child_list = Get-ChildItem -File -Path $dir.FullName
  foreach($file in $child_list) {
      if($file.Name -match ".crt") {
          $crt_path += $file.FullName
      }
  }
}
if($crt_path) {
  Write-Output "The cert $cert_name is used in the following configs:"
  foreach($p in $crt_path) {
    $p
  }
} else {
  throw "The cert $cert_name could not be found in any configs"
}