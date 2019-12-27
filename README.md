# get-VTFileReport
Use PowerShell to get VirusTotal report for an array of hashes.
Rate limited to 4 submissions per minute (per VT API restrictions).
If there are 1 or more positives, the number is returned in magenta.
