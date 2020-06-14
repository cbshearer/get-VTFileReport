# get-VTFileReport
- Use PowerShell to get VirusTotal report for an array of hashes.  
- This API is rate limited to 4 submissions per minute.  
- API documentation: https://developers.virustotal.com/reference#file-report

## To use this script:  
- Line 10: Enter your API key(Get your own VT API key here: https://www.virustotal.com/gui/join-us).  
- Line 25: Enter the hashes of the files you want to search for unless you will be using from the CLI.

## To from the CLI:   
- -h is for hash  
- Example:  
```
.\get-VTFileReport.ps1 -h ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436
```
## The following information is returned on the screen:
- Resource: the sha256 of what was submitted
- Scan date: last date the resource was scanned
- Positives: Number of positive results - if there are 1 or more positives, the number is returned in magenta.  
- Total: Number of engines that have scanned the file
- Permalink: Link to VT to see more information
- Percent: (positives/total) x 100 - if there are 1 or more positives, the number is returned in magenta.
