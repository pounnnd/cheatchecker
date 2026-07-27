<#
    ===========================================================================
    System Security & Trace Checker Script
    ===========================================================================
#>

Clear-Host

# --------------------------------------------------------------------------
# 1. ПРОВЕРКА ONEDRIVE И ОПРЕДЕЛЕНИЕ ПУТИ К РАБОЧЕМУ СТОЛУ
# --------------------------------------------------------------------------

# Проверка, запущен ли процесс OneDrive
$OneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
$IsOneDriveRunning = [bool]$OneDriveProcess

# Проверка наличия директории OneDrive
$OneDrivePath = "$env:USERPROFILE\OneDrive"
$HasOneDriveFolder = Test-Path $OneDrivePath

# Определение реального пути к Рабочему столу через Windows API 
# (работает корректно даже при включенной синхронизации OneDrive)
$DesktopPath = [Environment]::GetFolderPath("Desktop")

# Резервный вариант, если путь к Рабочему столу недоступен
if (-not $DesktopPath -or -not (Test-Path $DesktopPath)) {
    $DesktopPath = $PWD.Path
}

$OutputFile = Join-Path -Path $DesktopPath -ChildPath "Check_Result.txt"
$StartTime = Get-Date

function Generate-CheckerReport {
    Write-Output "==========================================================================="
    Write-Output "                       SYSTEM & TRACE SCAN REPORT                          "
    Write-Output "==========================================================================="
    
    # --------------------------------------------------------------------------
    # 1. TRACES & EXECUTION SCANNER
    # --------------------------------------------------------------------------
    $TraceInDefender = $false
    $FoundExecutables = [System.Collections.Generic.List[string]]::new()

    # Сканирование целевых каталогов
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

    # Проверка службы Защитника Windows
    $defService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if (-not $defService -or $defService.Status -ne "Running") {
        $TraceInDefender = $true
    }

    Write-Output "`n[!] SCAN RESULTS:"
    if ($TraceInDefender) {
        Write-Output "[-] Severe Traces found in Threat-Protection (Defender Disabled/Stopped)"
    } else {
        Write-Output "[+] Threat-Protection Service is active"
    }

    if ($FoundExecutables.Count -gt 0) {
        foreach ($exe in ($FoundExecutables | Select-Object -Unique)) {
            Write-Output "[-] Executable trace found: $exe"
        }
    } else {
        Write-Output "[+] No obvious standalone trace executables found in standard targets"
    }

    Write-Output ""
    Write-Output "-------------------"
    Write-Output "|      System     |"
    Write-Output "-------------------"
    Write-Output ""

    # --------------------------------------------------------------------------
    # 2. SYSTEM INFO & METRICS
    # --------------------------------------------------------------------------
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $bootTime = $os.LastBootUpTime
    $uptime = (Get-Date) - $bootTime

    Write-Output "Script-Run-Time: $($StartTime.ToString('dd.MM.yyyy HH:mm:ss'))"
    
    # Подключенные диски
    $drives = (Get-PSDrive -PSProvider FileSystem).Root -join " "
    Write-Output "Connected Drives: $drives"
    
    # Тома в реестре
    $regVolumes = (Get-ItemProperty -Path "HKLM:\SYSTEM\MountedDevices" -ErrorAction SilentlyContinue).PSObject.Properties | 
                  Where-Object { $_.Name -like "\DosDevices\*" } | 
                  ForEach-Object { $_.Name.Replace("\DosDevices\", "") }
    Write-Output "Volumes in Registry: $($regVolumes -join ', ')"

    Write-Output "Windows Version: $($os.Caption) (Build $($os.BuildNumber))"
    Write-Output "Windows Installation: $($os.InstallDate.ToString('dd.MM.yyyy'))"
    Write-Output "Last Boot up Time: $($bootTime.ToString('dd.MM.yyyy HH:mm:ss'))"

    # Статус OneDrive
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

    # Проверка активности Корзины
    $RecycleBin = Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($RecycleBin) {
        Write-Output "`nLast Recycle Bin Activity: $($RecycleBin.LastWriteTime.ToString('dd.MM.yyyy HH:mm:ss'))"
    } else {
        Write-Output "`nLast Recycle Bin Activity: Unknown / Empty"
    }

    # Подозрительное установленное ПО
    Write-Output "`nSuspicious Installs Check:"
    $Uninstalls = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", 
                                         "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                  Where-Object { $_.DisplayName -match "Process Hacker|System Informer|Cheat Engine|Process Explorer|Everything" }
    
    if ($Uninstalls) {
        foreach ($app in $Uninstalls) {
            Write-Output ("  - {0,-35} Version: {1}" -f $app.DisplayName, $app.DisplayVersion)
        }
    } else {
        Write-Output "  [+] No blacklisted analysis tools found in Registry"
    }

    # Кеш DNS
    Write-Output "`nLocal-DNS Entries (Filtered):"
    $dnsEntries = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -notmatch "local|microsoft|google|gta-five|discord|cloudflare" } | Select-Object -First 10
    if ($dnsEntries) {
        foreach ($dns in $dnsEntries) {
            Write-Output "  - Entry: $($dns.Entry) | Name: $($dns.Name)"
        }
    } else {
        Write-Output "  [+] Clean DNS Cache"
    }

    # Настройки GTA V settings.xml
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

    # Время работы системных процессов
    Write-Output "`nProcess Uptime Scan"
    Write-Output "-------------------"
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

    # --------------------------------------------------------------------------
    # 3. TAMPERING & PREFETCH ANALYSIS
    # --------------------------------------------------------------------------
    Write-Output ""
    Write-Output "-------------------"
    Write-Output "|    Tampering    |"
    Write-Output "-------------------"
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
        Write-Output "[!] Potential Manipulation in Prefetch (Missing expected PF records: $($missingPF -join ', '))"
    } else {
        Write-Output "[+] Prefetch integrity normal"
    }

    # Поиск скрытых файлов с пробелами
    $JournalUnicode = Get-ChildItem -Path "$env:LOCALAPPDATA\Temp", "C:\Windows\Prefetch" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\s{3,}" }
    if ($JournalUnicode) {
        foreach ($uFile in $JournalUnicode) {
            Write-Output "[-] Suspicious Unicode/Space manipulation found: $($uFile.FullName)"
        }
    } else {
        Write-Output "[+] No file name obfuscation found in Temp/Prefetch"
    }

    # --------------------------------------------------------------------------
    # 4. THREATS & AUTORUNS
    # --------------------------------------------------------------------------
    Write-Output ""
    Write-Output "-------------------"
    Write-Output "|      Threats    |"
    Write-Output "-------------------"
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

    # --------------------------------------------------------------------------
    # 5. SYSTEM EVENTS LOGS
    # --------------------------------------------------------------------------
    Write-Output ""
    Write-Output "-------------------"
    Write-Output "|      Events     |"
    Write-Output "-------------------"
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

# --------------------------------------------------------------------------
# СОХРАНЕНИЕ В ФАЙЛ
# --------------------------------------------------------------------------
Generate-CheckerReport | Out-File -FilePath $OutputFile -Encoding utf8

Write-Host "`n[+] Проверка успешно завершена!" -ForegroundColor Green
Write-Host "[+] Отчет сохранен по пути: $OutputFile" -ForegroundColor Yellow
