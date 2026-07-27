Clear-Host

$OneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
$IsOneDriveRunning = [bool]$OneDriveProcess
$OneDrivePath = "$env:USERPROFILE\OneDrive"
$HasOneDriveFolder = Test-Path $OneDrivePath

$DesktopPath = [Environment]::GetFolderPath("Desktop")
if (-not $DesktopPath -or -not (Test-Path $DesktopPath)) {
    $DesktopPath = $PWD.Path
}

$OutputFile = Join-Path -Path $DesktopPath -ChildPath "Check_Result.txt"
$StartTime = Get-Date

function Generate-CheckerReport {
    Write-Output "==========================================================================="
    Write-Output "                       SYSTEM & TRACE SCAN REPORT                          "
    Write-Output "==========================================================================="
    
    $TraceInDefender = $false
    $FoundExecutables = [System.Collections.Generic.List[string]]::new()

    $TargetPaths = @(
        "C:\archivefix", "C:\clumsy", "C:\umbr", "C:\Umbrella", "C:\zap", 
        "C:\projects", "C:\temp", "$env:USERPROFILE\Downloads", "$env:APPDATA", 
        "$env:LOCALAPPDATA", "C:\RAGEMP"
    )

    foreach ($path in $TargetPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $FoundExecutables.Add($_.FullName)
            }
        }
    }

    $defService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if (-not $defService -or $defService.Status -ne "Running") {
        $TraceInDefender = $true
    }

    Write-Output "`n[!] SCAN RESULTS:"
    if ($TraceInDefender) {
        Write-Output "[-] Severe Traces found: Defender Disabled / Stopped!"
    } else {
        Write-Output "[+] Defender Service is active"
    }

    if ($FoundExecutables.Count -gt 0) {
        foreach ($exe in ($FoundExecutables | Select-Object -Unique)) {
            Write-Output "[-] Executable trace found: $exe"
        }
    } else {
        Write-Output "[+] No obvious standalone trace executables found in standard targets"
    }

    Write-Output ""
    Write-Output "==================="
    Write-Output "|      System     |"
    Write-Output "==================="
    Write-Output ""

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $bootTime = $os.LastBootUpTime
    $uptime = (Get-Date) - $bootTime

    Write-Output "Script Start Time: $($StartTime.ToString('dd.MM.yyyy HH:mm:ss'))"
    
    $drives = (Get-PSDrive -PSProvider FileSystem).Root -join " "
    Write-Output "Connected Drives: $drives"
    
    $regVolumes = (Get-ItemProperty -Path "HKLM:\SYSTEM\MountedDevices" -ErrorAction SilentlyContinue).PSObject.Properties | 
                  Where-Object { $_.Name -like "\DosDevices\*" } | 
                  ForEach-Object { $_.Name.Replace("\DosDevices\", "") }
    Write-Output "Volumes in Registry: $($regVolumes -join ', ')"

    Write-Output "Windows Version: $($os.Caption) (Build $($os.BuildNumber))"
    Write-Output "Windows Installation Date: $($os.InstallDate.ToString('dd.MM.yyyy'))"
    Write-Output "Last Boot Time: $($bootTime.ToString('dd.MM.yyyy HH:mm:ss'))"

    Write-Output "`nOneDrive Status:"
    if ($IsOneDriveRunning) {
        Write-Output "  [!] OneDrive Process: ACTIVE (Running)"
    } else {
        Write-Output "  [+] OneDrive Process: INACTIVE (Not running)"
    }

    if ($HasOneDriveFolder) {
        Write-Output "  [-] OneDrive Directory: Present ($OneDrivePath)"
    } else {
        Write-Output "  [+] OneDrive Directory: Not found"
    }
    Write-Output "  [*] Target Desktop Path: $DesktopPath"

    $RecycleBin = Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($RecycleBin) {
        Write-Output "`nLast Recycle Bin Activity: $($RecycleBin.LastWriteTime.ToString('dd.MM.yyyy HH:mm:ss'))"
    } else {
        Write-Output "`nLast Recycle Bin Activity: Unknown / Empty"
    }

    Write-Output "`nSuspicious Installs Check:"
    $Uninstalls = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", 
                                         "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                  Where-Object { $_.DisplayName -match "Process Hacker|System Informer|Cheat Engine|Process Explorer|Everything|Scylla|x64dbg" }
    
    if ($Uninstalls) {
        foreach ($app in $Uninstalls) {
            Write-Output ("  - {0,-35} Version: {1}" -f $app.DisplayName, $app.DisplayVersion)
        }
    } else {
        Write-Output "  [+] No blacklisted analysis tools found in Registry"
    }

    Write-Output "`nLocal DNS Cache (Filtered):"
    $dnsEntries = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -notmatch "local|microsoft|google|gta-five|discord|cloudflare" } | Select-Object -First 10
    if ($dnsEntries) {
        foreach ($dns in $dnsEntries) {
            Write-Output "  - Entry: $($dns.Entry) | Name: $($dns.Name)"
        }
    } else {
        Write-Output "  [+] Clean DNS Cache"
    }

    Write-Output "`nMinus-Settings Check (GTA V settings.xml):"
    $gtaSettings = "$env:USERPROFILE\Documents\Rockstar Games\GTA V\settings.xml"
    if (-not (Test-Path $gtaSettings) -and $HasOneDriveFolder) {
        $gtaSettings = "$OneDrivePath\Documents\Rockstar Games\GTA V\settings.xml"
    }

    if (Test-Path $gtaSettings) {
        $minusLines = Select-String -Path $gtaSettings -Pattern 'value="-' -ErrorAction SilentlyContinue
        if ($minusLines) {
            foreach ($line in $minusLines) {
                Write-Output "    $($line.Line.Trim())"
            }
        } else {
            Write-Output "    [+] No negative values detected in settings.xml"
        }
    } else {
        Write-Output "    [!] settings.xml not found"
    }

    Write-Output "`nProcess Uptime Scan:"
    Write-Output "================================================"
    $criticalProcesses = @("dnscache", "dwm", "explorer", "lsass", "PcaSvc", "sysmain", "WSearch", "DiagTrack", "DPS")
    foreach ($procName in $criticalProcesses) {
        $p = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($p) {
            $pUptime = (Get-Date) - $p.StartTime
            $pStr = "{0}d {1:D2}:{2:D2}:{3:D2}" -f $pUptime.Days, $pUptime.Hours, $pUptime.Minutes, $pUptime.Seconds
            Write-Output ("{0,-15} Uptime: {1}" -f $procName, $pStr)
        } else {
            Write-Output ("{0,-15} STATUS: Stopped / Not Found" -f $procName)
        }
    }

    Write-Output "`nTotal System Uptime: {0} Days, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds

    Write-Output ""
    Write-Output "=========================================="
    Write-Output "| Deleted Executables Scan (USN Journal) |"
    Write-Output "=========================================="
    Write-Output ""

    try {
        $usnRaw = cmd /c "fsutil usn readjournal C: csv" 2>$null | Select-String "FILE_DELETE", "0x80000200", "0x00000200"
        $deletedExeList = [System.Collections.Generic.List[string]]::new()

        if ($usnRaw) {
            foreach ($line in $usnRaw) {
                $parts = $line.ToString().Split(',')
                if ($parts.Count -gt 0) {
                    $fileName = $parts[0].Trim('"')
                    if ($fileName -like "*.exe" -and $fileName -notmatch "Installer|Update|msi|setup|Edge|chrome|firefox") {
                        $deletedExeList.Add($fileName)
                    }
                }
            }
        }

        $uniqueDeleted = $deletedExeList | Select-Object -Unique -First 25
        if ($uniqueDeleted) {
            Write-Output "[!] Recently deleted executable files (.exe) found:"
            foreach ($delFile in $uniqueDeleted) {
                Write-Output "  [-] Deleted: $delFile"
            }
        } else {
            Write-Output "[+] No suspicious deleted .exe files found in USN Journal"
        }
    } catch {
        Write-Output "[!] Failed to read USN Journal (Admin privileges required)"
    }

    Write-Output ""
    Write-Output "==================="
    Write-Output "|    Tampering    |"
    Write-Output "==================="
    Write-Output ""
    
    $prefetchPath = "C:\Windows\Prefetch"
    $expectedPF = @("DISCORD", "REG", "CMD", "MPECMD RUN")
    $missingPF = @()

    if (Test-Path $prefetchPath) {
        foreach ($pf in $expectedPF) {
            $check = Get-ChildItem -Path $prefetchPath -Filter "*$pf*.pf" -ErrorAction SilentlyContinue
            if (-not $check) {
                $missingPF += $pf
            }
        }
    }

    if ($missingPF.Count -gt 0) {
        Write-Output "[!] Prefetch integrity warning (Missing records: $($missingPF -join ', '))"
    } else {
        Write-Output "[+] Prefetch integrity normal"
    }

    $JournalUnicode = Get-ChildItem -Path "$env:LOCALAPPDATA\Temp", "C:\Windows\Prefetch" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\s{3,}" }
    if ($JournalUnicode) {
        foreach ($uFile in $JournalUnicode) {
            Write-Output "[-] Suspicious Unicode/Space manipulation found: $($uFile.FullName)"
        }
    } else {
        Write-Output "[+] No file name obfuscation found in Temp/Prefetch"
    }

    Write-Output ""
    Write-Output "==================="
    Write-Output "|      Threats    |"
    Write-Output "==================="
    Write-Output ""

    Write-Output "User Startup Registry Keys Check (HKCU Run):"
    $RunKeys = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    if ($RunKeys) {
        foreach ($key in $RunKeys.psobject.Properties) {
            if ($key.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|Provider|Attach") {
                Write-Output "  - Autorun Entry: $($key.Name) = $($key.Value)"
            }
        }
    }

    Write-Output ""
    Write-Output "==================="
    Write-Output "|      Events     |"
    Write-Output "==================="
    Write-Output ""

    Write-Output "Defender Warning / Threat Events (Recent 5):"
    $defEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($defEvents) {
        foreach ($e in $defEvents) {
            Write-Output "  [$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] EventID: $($e.Id) | $($e.Message.Substring(0, [Math]::Min(80, $e.Message.Length)))"
        }
    } else {
        Write-Output "  [+] No recent Defender warning logs found"
    }

    Write-Output "`nService Installation Events (ID 7045/7040):"
    $svcEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045,7040} -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($svcEvents) {
        foreach ($se in $svcEvents) {
            Write-Output "  [$($se.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] EventID: $($se.Id) | $($se.Message.Substring(0, [Math]::Min(70, $se.Message.Length)))"
        }
    } else {
        Write-Output "  [+] No recent service change events"
    }

    Write-Output "`nPowerShell Execution Events (ID 4104):"
    $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 3 -ErrorAction SilentlyContinue
    if ($psEvents) {
        foreach ($pe in $psEvents) {
            Write-Output "  [$($pe.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] EventID: 4104 | Script block logged"
        }
    } else {
        Write-Output "  [+] PowerShell Operational log clear or disabled"
    }

    Write-Output ""
    Write-Output "==========================================================================="
    Write-Output "                           END OF REPORT                                   "
    Write-Output "==========================================================================="
}

Generate-CheckerReport | Out-File -FilePath $OutputFile -Encoding utf8

Write-Host "`n[+] Scan completed successfully!" -ForegroundColor Green
Write-Host "[+] Report saved to: $OutputFile" -ForegroundColor Yellow
