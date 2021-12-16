<#
    Log4j Vulnerability (CVE-2021-44228) file scanner [windows] :: build 8b/seagull
    Uses Florian Roth and Jai Minton's research (thank you!)
    RELEASED PUBLICLY for all MSPs, originally a Datto RMM ComStore Component.
    If you use code from this script, please credit Datto & seagull.

    The acceptable values for env:scanScope are:
    1: Scan files on Home Drive
    2: Scan files on fixed and removable drives
    3: Scan files on all detected drives, even network drives


    USER VARIABLES:
    scanScope  (1/2/3): just home drive / all fixed drives / all drives
    updateDefs (bool):  download the latest yara definitions from florian?
    mitigationAction   (Y/N/X): ternary option to enable/disable 2.10+ mitigation (or do nothing). https://twitter.com/CyberRaiju/status/1469505680138661890
#>

[CmdletBinding()]
param (
    [Parameter  ( Mandatory = $true )]
    [ValidateSet( 1,2,3 )]
    [Int16]$scanScope,

    [Parameter( Mandatory = $true )]
    [bool]$updateDefs,

    [Parameter  ( Mandatory = $true )]
    [ValidateSet( 'Mitigate','Reverse','No Action' )]
    [string]$mitigationAction
)


# Define vars
$output = @()
[string]$varch = [intPtr]::Size*8
$varDetection = 0
$varEpoch = [int][double]::Parse((Get-Date -UFormat %s))


# Don't want to max out the system, so let's find half of the available threads
$maxThreads = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors / 2


# What is this for?
$output += "Log4j/Log4Shell CVE-2021-44228 Scanning/Mitigation Tool (DKB/seagull/Datto)"
$output += "======================================================================="
if ($CS_CC_HOST) {
    $output += "Set up a File/Folder Size Monitor against devices"
    $output += "(File/s named $env:PROGRAMDATA\CentraStage\L4Jdetections.txt : is over : 0MB)"
    $output += "to alert proactively if this Component reports signs of infection."
    $output += "======================================================================="
}


# Is there already a detections.txt file?
if ((Test-Path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -ErrorAction SilentlyContinue)) {
    Rename-Item -Path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" "$env:PROGRAMDATA\CentraStage\$varEpoch-L4Jdetections.txt" -Force
    $output += "- An existing L4JDetections.txt file was found. It has been renamed to:"
    $output += "  $varEpoch-L4JDetections.txt"
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
        $output += "  (NOTE: This potentially makes a secure system vulnerable again! Use with caution!)"
        [Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","false","Machine")
    }

    'No Action' {
        $output += "- Not adjusting existing LOG4J_FORMAT_MSG_NO_LOOKUPS setting."
    }
}

# Map input variable scanScope to an actual value
switch ($scanScope) {
    1 {   
        $output += "- Scan scope: Home Drive"
        $varDrives=@($env:HomeDrive)
    }

    2 {   
        $output += "- Scan scope: Fixed & Removable Drives"
        $varDrives=Get-WmiObject -Class Win32_logicaldisk | Where-Object {$_.DriveType -eq 2 -or $_.DriveType -eq 3} | Where-Object {$_.FreeSpace} | ForEach-Object {$_.DeviceID}
    }

    3 {   
        $output += "- Scan scope: All drives, including Network"
        $varDrives=Get-WmiObject -Class Win32_logicaldisk | Where-Object {$_.FreeSpace} | ForEach-Object {$_.DeviceID}
    }
}

# If user opted to update yara rules, do that
if ($updateDefs) {
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    $varYaraNew = (New-Object System.Net.WebClient).DownloadString('https://github.com/Neo23x0/signature-base/raw/master/yara/expl_log4j_cve_2021_44228.yar')
    # Quick verification check
    if ($varYaraNew -match 'TomcatBypass') {
        Set-Content -Value $varYaraNew -Path yara.yar -Force
        $output += "- New YARA definitions downloaded."
    } else {
        $output += "! ERROR: New YARA definition download failed."
        $output += "  Falling back to built-in definitions."
        Copy-Item -Path expl_log4j_cve_2021_44228.yar -Destination yara.yar -Force
    }
} else {
    Copy-Item -Path expl_log4j_cve_2021_44228.yar -Destination yara.yar -Force
    $output += "- Not downloading new YARA definitions."
}

# Check yara32 and yara64 are there and that they'll run
foreach ($iteration in ('yara32.exe','yara64.exe')) {
    if (!(test-path $iteration)) {
        $output += "! ERROR: $iteration not found. It needs to be in the same directory as the script."
        $output += "  Download Yara from https://github.com/virustotal/yara/releases/latest and place them here."
        exit 1
    } else {
        $output += "- Verified presence of $iteration."
    }

    cmd /c "$iteration -v >nul 2>&1"
    if ($LASTEXITCODE -ne 0) {
        $output += "! ERROR: YARA was unable to run on this device."
        $output += "  The Visual C++ Redistributable is required in order to use YARA."
        if ($CS_CC_HOST) {
            $output += "  An installer Component is available from the ComStore."
        }
        exit 1
    }
}

# Start a logfile
$host.ui.WriteErrorLine("`r`nPlease expect some permissions errors as some locations are forbidden from traversal.`r`n=====================================================`r`n")
set-content -Path "log.txt" -Force -Value "Files scanned:"
Add-Content "log.txt" -Value "====================================================="
Add-Content "log.txt" -Value " :: Scan Started: $(get-date) ::"


# Get a list of all files-of-interest on the device (depending on scope) :: GCI is broken; permissions errors when traversing root dirs cause aborts (!!!)
$arrFiles=@()
foreach ($drive in $varDrives) {
    Get-ChildItem "$drive\" -force | Where-Object {$_.PSIsContainer} | ForEach-Object {
        Get-ChildItem -path "$drive\$_\" -rec -force -include *.jar,*.log,*.txt -ErrorAction 0 | ForEach-Object {
            $arrFiles+=$_.FullName
        }
    }
}

# Scan i: JARs containing vulnerable Log4j code
$output += "====================================================="
$output += "- Scanning for JAR files containing potentially insecure Log4j code..."
$arrFiles | Where-Object {$_ -match '\.jar$'} | ForEach-Object {
    if (select-string -Quiet -Path $_ "JndiLookup.class") {
        $output += "! ALERT: Potentially vulnerable file at $($_)!"
        if (!(test-path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -ErrorAction SilentlyContinue)) {set-content -path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -Value "! CAUTION !`r`n$(get-date)"}
        Add-Content "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -Value "POTENTIALLY VULNERABLE JAR: $($_)"
        $varDetection = 1
    }
}

# Scan ii: YARA for logfiles & JARs
$output += "====================================================="
$output += "- Scanning LOGs, TXTs and JARs for common attack strings via YARA scan......"
foreach ($file in $arrFiles) {
    if ($file -match 'CentraStage' -or $file -match 'L4Jdetections\.txt') {
        #do nothing -- this isn't a security threat; we're looking at the pathname of the log, not the contents
    } else {
        #add it to the logfile, with a pause for handling
        try {
            Add-Content "log.txt" -Value $file -ErrorAction Stop
        } catch {
            Start-Sleep -Seconds 1
            Add-Content "log.txt" -Value $file -ErrorAction SilentlyContinue
        }

        # Scan it
        clear-variable yaResult -ErrorAction SilentlyContinue
        $yaResult=cmd /c "yara$varch.exe `"yara.yar`" `"$file`" -s --threads=$maxThreads"
        if ($yaResult) {
            # Sound an alarm
            $output += "====================================================="
            $varDetection = 1
            $output += "! DETECTION:"
            $output += $yaResult
            # Write to a file
            if (!(test-path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -ErrorAction SilentlyContinue)) {set-content -path "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -Value "! INFECTION DETECTION !`r`n$(get-date)"}
            Add-Content "$env:PROGRAMDATA\CentraStage\L4Jdetections.txt" -Value $yaResult
        }
    }
}

Add-Content "log.txt" -Value " :: Scan Finished: $(get-date) ::"

if ($varDetection -eq 1) {
    $output += "====================================================="
    $output += "! Evidence of one or more Log4Shell attack attempts has been found on the system."
    $output += "  The location of the files demonstrating this are noted in the following log:"
    $output += "  $env:PROGRAMDATA\CentraStage\L4Jdetections.txt"
} else {
    $output += "- There is no indication that this system has received Log4Shell attack attempts ."
}

$output += `r
$output += "Datto recommends that you follow best practices with your systems by implementing WAF rules,"
$output += "mitigation and remediation recommendations from your vendors. For more information on Datto's"
$output += "response to the log4j vulnerabilty, please refer to https://www.datto.com/blog/dattos-response-to-log4shell."