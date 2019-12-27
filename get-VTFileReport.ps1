## Search VirusTotal for a file hash
## Chris Shearer
## 9.4.2019
## VirusTotal Public API: https://developers.virustotal.com/reference#file-report

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
    $samples = @("ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
    "614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f")

## Loop through hashes
    foreach ($hash in $samples)
        {
            ## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
                if ($samples.count -ge 4) {$sleepSeconds = 15}
                else {$sleepTime = 1 }

            $VTresult = submit-VTHash($hash)

            ## Display results
                Write-Host "==================="
                Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTresult.resource
                Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTresult.scan_date
                Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTresult.positives
                Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTresult.total
                Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTresult.permalink
                

                Start-Sleep -seconds $sleepTime
        }
