param($apikey)
$sites = (Get-Content ./todelete.txt | ConvertFrom-Json).sites | select-object -Unique
if($sites.count -eq 1) {
    $site_name = $sites
} else {
    $site_name = "Listed"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$API_CODE=$apikey
$API_URL="https://euromoney-snow-change-tracking.azurewebsites.net/api/RaiseSnowChange"
$WEB_SITE=$site_name
$PROJECT="iis_site_decom"
$ENVIRONMENT="production"
$SUMMARY="The following sites are to be decommissioned:$(foreach($site in $sites){$("`n$site")})"

$req_data = @{
    project=$PROJECT;
    environment=$ENVIRONMENT;
    web_site=$WEB_SITE;
    summary=$SUMMARY
}

$req_headers = @{
    'x-functions-key'=$API_CODE;
}

$json_data = ConvertTo-Json -InputObject $req_data


try {
    $res = Invoke-WebRequest -Uri $API_URL -Method Post -Body $json_data -ContentType "application/json" -Headers $req_headers
    $json_res = $res.Content | ConvertFrom-Json
    $change_sys_id = $json_res.change_sys_id
    $change_sys_id
    $change_sys_id > ./changeid.txt
    #Write-Host $json_res.change_sys_id
    Write-Host "SNow change number: $($json_res.change_number)"
    #Write-Host "##teamcity[setParameter name='env.change_sys_id' value='$change_sys_id']"
} catch {
    Write-Host $Error[0].Exception.GetType().FullName
    Throw ("Could not create change. {0}" -f $Error[0])
}