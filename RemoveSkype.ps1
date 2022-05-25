# RemoveSkype

<#
.SYNOPSIS
    Stop Skype for Business from launching at startup
.DESCRIPTION
    Prompt user to enter target
        a. If the target ends with .csv, it is assumed to be a file path and the script will run Import-Csv against that path
        b. If the target contains anything else, this is assumed to be a hostname and the script will try to connect to that host
    Once a target is defined, the script deletes various registry keys from HKLM where Skype/Lync may still exist and deletes .exe and .lnk files from shared locations: Office ProgramFiles, and
    StartUp ProgramData. To completely remove Skype we need to delete the Lync reg entry for each user. Instead of loading each NTUSER.DAT, modifying it, then unloading it, I decided to add a
    new task to Active Setup. This will use reg.exe to remove the entry from HKCU the first time that user signs in.
    Output is sent to a log in local C:\Temp so we can go back later to try again for failures.
.NOTES
    v3.1.1
#>

# Elevate to admin
if ( -not ( [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() ).IsInRole( [Security.Principal.WindowsBuiltInRole] 'Administrator') ) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Create a log 
function Write-Log
{
    Param ([string]$LogEntry)
    $TimeStamp = Get-Date -Format s
    Add-Content -Path $LogFile -Value "$TimeStamp,$LogEntry"
}
$LogFile = 'C:\Temp\SkypeRemoval.csv'

# Define the Target - input a path to Import-Csv, a Division-level OU, or computername
Write-Host 'To import a CSV, specify the path e.g. C:\Temp\SkypeTargets.csv'
Write-Host 'To select a specific computer, enter the hostname e.g. DOL01FV-DTWX037'
Write-Host ''
$Target = Read-Host -Prompt 'Enter target'
Clear-Host

Add-Content -Path $LogFile -Value '-------------------------,---------,Begin Removing Skype --------------------------------------------'

# Translate Target to HostList
if ($Target -like '*.csv') {
    $HostList = Import-Csv -Path "$Target"
    Write-Log "INFO,Importing CSV $Target..."
    Write-Host "INFO - Importing CSV $Target..."
    Write-Host ''
} else {
    $HostList = $Target
    Write-Log "INFO,Running against $Target..."
    Write-Host "INFO - Running against $Target..."
    Write-Host ''
}

# Main routine that runs against each host in the hostlist
foreach ($Computer in $HostList) {
    # If a single hostname is entered, use it; otherwise get the Name property from the CSV
    if ($HostList -eq $Target) {
        $HostName = $Target
    } else {
        $HostName = $Computer.Name
    }

    # Try to create a new PSSession on $HostName
    Write-Host "INFO - Create PSSession on $HostName" -ForegroundColor Cyan
    try {
        $RemoteSession = New-PSSession -ComputerName $HostName
        Invoke-Command -Session $RemoteSession -ScriptBlock {
            $HostName = hostname

            # Create C:\Temp so we have somewhere to put the GUID (either the pre-existing one we find, or the one we create)
            New-Item -Path "\\$HostName\C$\" -Name 'Temp' -ItemType Directory -Force | Out-Null

            # Check if Active Setup is already configured to remove Skype. If so, skip it; else configure it
            $SkypeTask = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*' |
                Get-ItemProperty -Name '(Default)' -ErrorAction SilentlyContinue |
                Where-Object { ("$_.(Default)" -match 'Remove Skype for Business') }
            $SkypeGUID = $SkypeTask.PSChildName

            if ($SkypeTask) {
                Write-Host "INFO - Active Setup component $SkypeGUID is already configured on $HostName." -ForegroundColor Green
                Set-Content -Path 'C:\Temp\SkypeRemoval.txt' -Value "$SkypeGUID"
            } else {
                # Stop Skype, remove a bunch of HKLM keys, and shared .exe and .lnk files
                Write-Host 'INFO - Stop Skype'
                Stop-Process -Name 'Lync' -Force 2> $null
                Write-Host INFO - 'Remove HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\UCAddin.LyncAddin.1'
                Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\UCAddin.LyncAddin.1' -Recurse 2> $null
                Write-Host 'INFO - Remove HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}'
                Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}' -Recurse 2> $null
                Write-Host 'INFO - Remove HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}'
                Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}' -Recurse 2> $null
                Write-Host 'INFO - Remove HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}'
                Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}' -Recurse 2> $null
                Write-Host 'INFO - Remove HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}'
                Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}' -Recurse 2> $null
                Write-Host "INFO - Remove $env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Skype for Business.lnk"
                Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Skype for Business.lnk" 2> $null
                Write-Host "INFO - Remove $env:ProgramFiles\Microsoft Office\root\Office16\lync.exe"
                Remove-Item -Path "$env:ProgramFiles\Microsoft Office\root\Office16\lync.exe" 2> $null

                # Generate a new GUID for Active Setup and create the key, using reg.exe to delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Lync at next logon
                $NewGUID = New-Guid
                Write-Host "INFO - Add Active Setup task on $HostName"
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\" -Name "{$NewGUID}" | Out-Null
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{$NewGUID}" -Name '(Default)' -PropertyType String -Value 'Remove Skype for Business' -Force | Out-Null
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{$NewGUID}" -Name 'StubPath' -PropertyType String -Value 'reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Lync /f' -Force | Out-Null
                Write-Host "INFO - Active Setup component {$NewGUID} has been created!" -ForegroundColor Green
                Set-Content -Path 'C:\Temp\SkypeRemoval.txt' -Value "{$NewGUID}"
            }
        }

        # Close the PSSession we opened, read the GUID from remote C:\Temp and write it to the log, then delete the .txt file
        Get-PSSession | Remove-PSSession
        $FinalGUID = Get-Content -Path "\\$HostName\C$\Temp\SkypeRemoval.txt"
        Remove-Item -Path "\\$HostName\C$\Temp\SkypeRemoval.txt"
        Write-Log "INFO,Active Setup component $FinalGUID is configured on $HostName"
        Write-Host "------------------------------------------------" -ForegroundColor Cyan    
    } catch {
        # Catch-all in case New-PSSession fails to connect to the host
        Write-Log "ERR!,Could not connect to $HostName"
        Write-Host "ERR! - Could not connect to $HostName" -ForegroundColor Yellow
        Write-Host "------------------------------------------------" -ForegroundColor Cyan
    }
}

Add-Content -Path $LogFile -Value '-------------------------,---------,End Removing Skype ----------------------------------------------'
Write-Host ''
Write-Host "Review the log at $LogFile if desired." -ForegroundColor Cyan
Read-Host -Prompt 'Operation complete. Press Enter to exit'
