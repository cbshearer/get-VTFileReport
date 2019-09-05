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
    $hash = "Initial
