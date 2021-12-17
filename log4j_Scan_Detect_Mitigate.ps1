Function Test-log4jVulnerability {
    <#
        .Description
        Seaches machine for JAR files, scans JAR files with the yar vulnerability scanner tool,
        reports vulnerabilities if present, reports exploit if found, and applies mitigation
        if mitigation applied is set at function call.

        .Parameter scanScope
        1: Scan files on Home Drive
        2: Scan files on fixed and removable drives
        3: Scan files on all detected drives, even network drives

        .Parameter mitigationAction
        Available Values:

        Mitigate: Apply mitigation
        Reverse: Reverse mitigation
        None: Take no mitigation actions


        Credits
        Initial script concept and testing credit to Datto & seagull
    #>

    [CmdletBinding()]
    param (
        [Parameter  (
            Mandatory = $true,
            HelpMessage = "1: Scan files on Home Drive, 2: Scan files on fixed and removable drives, 3: Scan files on all detected drives, even network drives"
        )]
        [ValidateSet( 1,2,3 )]
        [Int16]$scanScope,

        [Parameter  ( 
            Mandatory = $true,
            HelpMessage = "Mitigate: Apply mitigation, Reverse: Reverse mitigation, None: Take no mitigation actions"
        )]
        [ValidateSet( 'Mitigate','Reverse','None' )]
        [string]$mitigationAction
    )


    # Output Helper Functionsfunction Invoke-Output {
        function Invoke-Output {
            param ([string[]]$output)
            Write-Output ($output -join "`n")
        }


    # Define vars
    $output = @()
    $varDetection = 0
    $varEpoch = [int][double]::Parse((Get-Date -UFormat %s))
    $osArch = Get-WmiObject win32_operatingsystem | Select-Object -ExpandProperty OSArchitecture
    $yaraDir = $env:windir + '\LTSVc\utilities\yara'
    $yaraZip = $yaraDir + '\yara.zip'
    $yaraExe = $yaraDir + '\yara32.exe'
    $yaraYar = $yaraDir + '\yara.yar'
    $outputLog = $yaraDir + '\log4jScanLogs.txt'
    $detectionLog = $yaraDir + '\DETECTION_log4jScanLogs.txt'


    # Set the download URL of the yara zip file
    switch ($osArch) {
        '64-Bit' {
            $zipUrl = 'https://github.com/VirusTotal/yara/releases/download/v4.1.3/yara-v4.1.3-1755-win64.zip'
            $yaraExe = $yaraDir + '\yara64.exe'
        }

        '32-Bit' {
            $zipUrl = 'https://github.com/VirusTotal/yara/releases/download/v4.1.3/yara-v4.1.3-1755-win32.zip'
            $yaraExe = $yaraDir + '\yara32.exe'
        }
    }


    # Create required dirs
    if (!(Test-Path -Path $yaraDir)) {
        New-Item -Path $yaraDir -ItemType Directory | Out-Null
    }


    # Download Pre-Req Files
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        (New-Object System.Net.WebClient).DownloadFile($zipUrl,$yaraZip)
        $output += "Successfully downloaded the yara utility"
    } catch {
        $output += "Failed to download the yara utility, exiting script. Full error output: $Error"
        Invoke-Output $output
        break
    }


    try {
        $varYaraNew = (New-Object System.Net.WebClient).DownloadString('https://github.com/Neo23x0/signature-base/raw/master/yara/expl_log4j_cve_2021_44228.yar')
        Set-Content -Value $varYaraNew -Path $yaraYar -Force
    } catch {
        $output += "Failed to download the yara definition updates, exiting script. Full error output: $Error"
        Invoke-Output $output
        break
    }



    # Unzip yara
    try {
        If (!(Test-Path -Path $yaraExe)) {
            [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
            [System.IO.Compression.ZipFile]::ExtractToDirectory($yaraZip,$yaraDir)
        }
    } catch {
        $output += "Failed to unzip yara. Full error output: $Error"
        Invoke-Output $output
        break
    }


    # Don't want to max out the system, so let's find half of the available threads
    $maxThreads = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors / 2


    $output += "Log4j/Log4Shell CVE-2021-44228 Scanning/Mitigation Tool (DKB/seagull/Datto)"
    $output += "======================================================================="


    # Is there already a detections.txt file?
    if ((Test-Path $detectionLog -ErrorAction SilentlyContinue)) {
        Rename-Item -Path $detectionLog "$yaraDir\$varEpoch-DETECTION_log4jScanLogs.txt" -Force
        $output += "- An existing DETECTION_log4jScanLogs.txt file was found. It has been renamed to:"
        $output += "$varEpoch-DETECTION_log4jScanLogs.txt"
    }


    # Did the user turn NOLOOKUPS (2.10+ mitigation) on?
    switch ($mitigationAction) {
        'Mitigate' {   
            if ([System.Environment]::GetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS','machine') -eq 'true') {
                $output += "- Log4j 2.10+ exploit mitigation (LOG4J_FORMAT_MSG_NO_LOOKUPS) already set."
            } else {
                $output += "- Enabling Log4j 2.10+ exploit mitigation: Enable LOG4J_FORMAT_MSG_NO_LOOKUPS"
                [Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","true","Machine")
            }
        }

        'Reverse' { 
            $output += "- Reversing Log4j 2.10+ explot mitigation (enable LOG4J_FORMAT_MSG_NO_LOOKUPS)"
            $output += "  (NOTE: This potentially makes a secure system vulnerable again!Use with caution!)"
            [Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","false","Machine")
        }

        'None' {
            $output += "- Not adjusting existing LOG4J_FORMAT_MSG_NO_LOOKUPS setting."
        }
    }


    # Map input variable scanScope to an actual value
    switch ($scanScope) {
        1 {   
            $output += "- Scan scope: Home Drive"
            $varDrives = @($env:HomeDrive)
        }

        2 {   
            $output += "- Scan scope: Fixed & Removable Drives"
            $varDrives = Get-WmiObject -Class Win32_logicaldisk | Where-Object {$_.DriveType -eq 2 -or $_.DriveType -eq 3} | Where-Object {$_.FreeSpace} | ForEach-Object {$_.DeviceID}
        }

        3 {   
            $output += "- Scan scope: All drives, including Network"
            $varDrives = Get-WmiObject -Class Win32_logicaldisk | Where-Object {$_.FreeSpace} | ForEach-Object {$_.DeviceID}
        }
    }


    # Check yara32 and yara64 are there and that they'll run
    cmd /c "$yaraExe -v >nul 2>&1"


    # Start a logfile
    Set-Content -Path $outputLog -Force -Value "Files scanned:"
    Add-Content $outputLog -Value "Please expect some permissions errors as some locations are forbidden from traversal."
    Add-Content $outputLog -Value "====================================================="
    Add-Content $outputLog -Value " :: Scan Started: $(Get-Date) ::"


    # Get a list of all files-of-interest on the device (depending on scope) :: GCI is broken; permissions errors when traversing root dirs cause aborts (!!!)
    $arrFiles = @()
    foreach ($drive in $varDrives) {
        Get-ChildItem "$drive\" -Force | Where-Object {$_.PSIsContainer} | ForEach-Object {
            Get-ChildItem -Path "$drive\$_\" -Rec -Force -Include *.jar,*.log,*.txt -ErrorAction 0 | ForEach-Object {
                $arrFiles += $_.FullName
            }
        }
    }


    # Scan i: JARs containing vulnerable Log4j code
    $output += "====================================================="
    $output += "- Scanning for JAR files containing potentially insecure Log4j code..."
    $arrFiles | Where-Object {$_ -match '\.jar$'} | ForEach-Object {
        if (select-string -Quiet -Path $_ "JndiLookup.class") {
            $output += "!ALERT: Potentially vulnerable file at $($_)!"
            if (!(Test-Path $detectionLog -ErrorAction SilentlyContinue)) {
                Set-Content -Path $detectionLog -Value "!CAUTION`r`n$(Get-Date)"
            }
            Add-Content $detectionLog -Value "POTENTIALLY VULNERABLE JAR: $($_)"
            $varDetection = 1
        }
    }


    # Scan ii: YARA for logfiles & JARs
    $output += "====================================================="
    $output += "- Scanning LOGs, TXTs and JARs for common attack strings via YARA scan......"
    foreach ($file in $arrFiles) {
        if ($file -match 'CentraStage' -or $file -match 'DETECTION_log4jScanLogs\.txt') {
            #do nothing -- this isn't a security threat; we're looking at the pathname of the log, not the contents
        } else {
            #add it to the logfile, with a pause for handling
            try {
                Add-Content $outputLog -Value $file -ErrorAction Stop
            } catch {
                Start-Sleep -Seconds 1
                Add-Content $outputLog -Value $file -ErrorAction SilentlyContinue
            }

            # Scan it
            Clear-Variable yaResult -ErrorAction SilentlyContinue
            $yaResult = cmd /c "$yaraExe `"$yaraYar`" `"$file`" -s --threads=$maxThreads"
            if ($yaResult) {
                # Sound an alarm
                $output += "====================================================="
                $varDetection = 1
                $output += "!DETECTION:"
                $output += $yaResult
                # Write to a file
                if (!(Test-Path $detectionLog -ErrorAction SilentlyContinue)) {
                    Set-Content -Path $detectionLog -Value "!INFECTION DETECTION !`r`n$(Get-Date)"
                    $output += "!DETECTION: See last 50 lines of output below, and see the full local output at $detectionLog"
                    $output += Get-Content -Path $detectionLog -Tail 50
                }
                Add-Content $detectionLog -Value $yaResult
            }
        }
    }


    Add-Content $outputLog -Value ":: Scan Finished: $(Get-Date) ::"


    if ($varDetection -eq 1) {
        $output += "====================================================="
        $output += "!EVIDENCE of one or more Log4Shell vulnerabilities and possible exploit has been found on the system."
        $output += "The location of the files demonstrating this are noted in the following log:"
        $output += "See last 50 lines of logged evidence below, and see the full local output at $detectionLog"
        $output += Get-Content -Path $detectionLog -Tail 50
    } else {
        $output += "- There is no indication that this system has received Log4Shell attack attempts ."
    }


    $output += "DKB recommends that you follow best practices with your systems by implementing WAF rules,"
    $output += "mitigation and remediation recommendations from your vendors."


    Invoke-Output $output
    break
}