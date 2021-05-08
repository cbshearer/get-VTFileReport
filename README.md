# get-VTFileReport

- Use PowerShell to get VirusTotal report for an array of hashes.  
- This API is rate limited to 4 submissions per minute.  
- VirusTotal [API documentation](https://developers.virustotal.com/reference#file-report)

## To use the module

- Import the module.

```PowerShell
PS C:\temp> Import-Module .\get-VTFileReport.psm1
```

- If you want to install the module for long-term use
  - See [Microsoft documentation](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-7).
  - Shortcut - just copy to its own folder in this location: $Env:ProgramFiles\WindowsPowerShell\Modules

```PowerShell
PS C:\temp> copy .\get-VTFileReport.psm1 $Env:ProgramFiles\WindowsPowerShell\Modules\get-VTFileReport\get-VTFileReport.psm1
```

- Line 14: Enter your API key 
  - Sign up for your own [VirusTotal API key](https://www.virustotal.com/gui/join-us). 
- Mandatory parameter:
  - -h is for hash.
  - Comma separated for multiples.
- Examples:  

```PowerShell
get-VTFileReport -h ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436
get-VTFileReport -h 100F6AB2737F1AF0746D6650D9DDD0E4B56A9A8583DD087DF64DECA62E77F65B,614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f
```

## The following information is returned on the screen

- Resource: the sha256 of what was submitted.
- Scan date: last date the resource was scanned.
- Positives: Number of positive results.  
- Total: Number of engines that have scanned the file.
- Permalink: Link to VT to see more information.
- Percent: Percent of positive results.
