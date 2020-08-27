## Search VirusTotal for a file hash
## Chris Shearer
## 26-Aug-2020
## VirusTotal Public API: https://developers.virustotal.com/reference#file-report


Function get-VTFileReport 
{
    ## Accept CLI parameters
        param ([Parameter(Mandatory=$true)] [array]$h)

    ## Get your own VT API key here: https://www.virustotal.com/gui/join-us
        $VTApiKey = "xxxxxxxxxxxxxx"

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
    }

    Export-ModuleMember -Function get-VTFileReport