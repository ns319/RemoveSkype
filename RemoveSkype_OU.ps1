# StopSkype

<#
.SYNOPSIS
    Stop Skype for Business from launching at startup
.DESCRIPTION
    Prompt for an OU and delete various registry keys from HKLM where Skype/Lync may still exist, remove the Lync entry from the Run key for the current user, and delete .exe and .lnk files from
    shared locations: Office ProgramFiles, and StartUp ProgramData. To completely remove Skype we need to delete the Lync reg entry for each user, so get a list of all users and
    send it to the 'foreach' command, load each reg hive from NTUSER.DAT, remove the entry, then unload the hive.
.NOTES
    I could not splat the User names from any directory other than C:\Users. No idea why; I probably missed something. But using Set-Location first works fine as a workaround.
    
    HKEY_USERS is not a default PSDrive, so we need to add it before we can use it.

    !-----! !-----! IMPORTANT !-----! !-----!
    This script WILL generate errors. I loaded NTUSER.DAT from every profile listed in C:\Users, which includes profiles like DOL_DA_USER, Default, etc. These profiles
    don't have entries for Lync because they have never run Lync/Skype, so you'll see errors to that effect. I removed 'Public' from the UserList to avoid the Access Denied
    error when trying to unload the reg hive; I think this is because the Remove-Item command opens a handle on the hive that doesn't get closed because none of the keys
    exist in this hive, so reg.exe can't unload the hive until the handle is closed. I could force the handle to close, but it's easier to just not open it to begin with.
    v1.4.3
#>

# Elevate to admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

$OU = Read-Host -Prompt "Enter OU"
$HostList = Get-ADComputer -SearchBase "ou=computers,ou=$OU,ou=whateverelse,dc=something" -Filter * | Select-Object -Property Name

foreach ($HostName in $HostList) {
    $HostName = $HostName.Name
    Write-Host "Create PSSession on $HostName" -ForegroundColor Cyan
    $RemoteSession = New-PSSession -ComputerName $HostName
    Write-Host "Invoke Command on $HostName" -ForegroundColor Cyan
    Invoke-Command -Session $RemoteSession -ScriptBlock {
        $HostName = hostnameq
        Write-Host "Stop Lync on $HostName" -ForegroundColor Cyan
        Stop-Process -Name 'Lync' -Force
        Write-Host "Remove HKLM LyncAddin from $HostName" -ForegroundColor Cyan
        Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\UCAddin.LyncAddin.1' -Recurse
        Write-Host "Remove HKLM BHO from $HostName" -ForegroundColor Cyan
        Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}' -Recurse
        Write-Host "Remove HKLM WOW6432 BHO from $HostName" -ForegroundColor Cyan
        Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}' -Recurse
        Write-Host "Remove HKLM Extension from $HostName" -ForegroundColor Cyan
        Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}' -Recurse
        Write-Host "Remove HKLM WOW6432 Extension from $HostName" -ForegroundColor Cyan
        Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}' -Recurse
        Write-Host "Remove HKCU Run from $HostName" -ForegroundColor Cyan
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name 'Lync' -Force
        Write-Host "Remove StartUp .lnk from $HostName" -ForegroundColor Cyan
        Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Skype for Business.lnk" -Verbose
        Write-Host "Remove OfficeRoot .exe from $HostName" -ForegroundColor Cyan
        Remove-Item -Path "$env:ProgramFiles\Microsoft Office\root\Office16\lync.exe" -Verbose
        
        # This only worked for me from the C:\Users directory; anywhere else and the command would fail. Idk why?
        Set-Location -Path 'C:\Users'

        $UserList = @(Get-ChildItem -Path C:\Users).Name

        # HKU: is not a default PSDrive, so add it
        Write-Host "Create HKU PSDrive on $HostName"
        New-PSDrive -Name 'HKU' -PSProvider 'Registry' -Root 'HKEY_USERS'
        
        foreach ($User in $UserList) {
            Write-Host "Load reg hive for $User" -ForegroundColor Cyan
            reg.exe load HKU\$User "C:\Users\$User\NTUSER.DAT"
            Write-Host "Remove HKU Run for $User" -ForegroundColor Cyan
            Remove-ItemProperty -Path "HKU:\$User\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name 'Lync'
            Write-Host "Unload reg hive for $User" -ForegroundColor Cyan
            reg.exe unload HKU\$User
        }
        Write-Host "------------------------------------------------" -ForegroundColor Cyan    
    }
    Write-Host "------------------------------------------------" -ForegroundColor Cyan
}
Write-Host "------------------------------------------------" -ForegroundColor Cyan

Read-Host -Prompt "Press Enter to exit"
