# get-VTFileReport
- Use PowerShell to get VirusTotal report for an array of hashes.  
- This API is rate limited to 4 submissions per minute.  
- If there are 1 or more positives, the number is returned in magenta.  
# To use this script:  
- Line 10: Enter your API key(Get your own VT API key here: https://www.virustotal.com/gui/join-us).  
- Line 25: Enter the hashes of the files you want to search for unless you will be using from the CLI.  
# To use this script from the CLI there is only 1 mandatory paramteter:   
- -h is for hash  
# Example:  
> .\get-VTFileReport-2.ps1 -h ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436
