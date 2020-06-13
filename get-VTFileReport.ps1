## Search VirusTotal for a file hash
## Chris Shearer
## 4-sep-2019
## VirusTotal Public API: https://developers.virustotal.com/reference#file-report

## Accept CLI parameters
    param ($h)

## Get your own VT API key here: https://www.virustotal.com/gui/join-us
    $VTApiKey = "xxxxx"

## Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function submit-VTHash($VThash)
{
    $VTbody = @{resource = $VThash; apikey = $VTApiKey}
    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

    return $vtResult
}

## Samples
    if ($h) {$samples = $h}
    else    {$samples = @("ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
                          "614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f")}

## Loop through hashes
    foreach ($hash in $samples)
        {
            ## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
                if ($samples.count -ge 4) {$sleepTime = 15}
                else {$sleepTime = 1 }
            
            ## Submit the hash!
                $VTresult = submit-VTHash($hash)
            
            ## Color positive results
                if ($VTresult.positives -ge 1) {
                    $fore = "Magenta"
                    $VTpct = (($VTresult.positives) / ($VTresult.total)) * 100
                    $VTpct = [math]::Round($VTpct,2)
                }
                else {
                    $fore = (get-host).ui.rawui.ForegroundColor
                    $VTpct = 0
                }

            ## Display results
                Write-Host "==================="
                Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTresult.resource
                Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTresult.scan_date
                Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTresult.positives -f $fore
                Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTresult.total
                Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTresult.permalink
                Write-Host -f Cyan "Percent     : " -NoNewline; Write-Host $VTpct "%" -f $fore
                
                Start-Sleep -seconds $sleepTime
        }
