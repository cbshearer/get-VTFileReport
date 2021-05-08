## Search VirusTotal for a file hash
## Chris Shearer
## 26-Aug-2020
## VirusTotal Public API: https://developers.virustotal.com/reference#file-report


Function get-VTFileReport 
{
    ## Accept CLI parameters
        param ([Parameter(Mandatory=$true)] [array]$h)

    ## Get your own VT API key here: https://www.virustotal.com/gui/join-us
        $VTApiKey = "xxxxxxxxxxx"

    ## Set TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    ## Samples
        if ($h) {$samples = $h}
        else {write-host -f magenta "No hash found, exiting."}

    ## Loop through hashes
        foreach ($hash in $samples)
            {
                ## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
                    if ($samples.count -ge 4) {$sleepTime = 15}
                    else {$sleepTime = 1 }
                
                ## Submit the hash!
                    $VTbody = @{resource = $hash; apikey = $VTApiKey}
                    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

                ## Calculate percentage if there is a result
                    if ($VTresult.positives -ge 1) {
                        $VTpct = (($VTresult.positives) / ($VTresult.total)) * 100
                        $VTpct = [math]::Round($VTpct,2)
                    }
                    else {
                        $VTpct = 0
                    }
                ## Custom Object for data output
                    [PSCustomObject]@{
                        resource    = $VTresult.resource
                        scan_date   = $VTresult.scan_date
                        positives   = $VTresult.positives
                        total       = $VTresult.total
                        permalink   = $VTresult.permalink
                        percent     = $VTpct
                    }
                    
                    Start-Sleep -seconds $sleepTime
             
            }
    }

    Export-ModuleMember -Function get-VTFileReport
