## Search VirusTotal for a file hash
## Chris Shearer
## 9.4.2019
## VirusTotal Public API: https://developers.virustotal.com/reference#file-report

## set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Get your own VT API key here: https://www.virustotal.com/gui/join-us
    $VTApiKey = "1234567890abcdefedcba0987654321"

Function submit-VTHash($VThash)
{
    $VTbody = @{resource = $VThash; apikey = $VTApiKey}
    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

    return $vtResult
}

## Example hash
    $hash = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436" 

## Submit the hash to the function
    $VTresult = submit-VTHash($hash)

## Display results
    Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTresult.resource
    Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTresult.scan_date
    Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTresult.positives
    Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTresult.total
    Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTresult.permalink
