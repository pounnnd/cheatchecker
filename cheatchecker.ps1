<#
    ===========================================================================
    System Security & Trace Checker Script (Full Version + USN Journal Scanner)
    ===========================================================================
#>

Clear-Host

# --------------------------------------------------------------------------
# 1. ПРОВЕРКА ONEDRIVE И ОПРЕДЕЛЕНИЕ ПУТИ К РАБОЧЕМУ СТОЛУ
# --------------------------------------------------------------------------

# Проверка процесса и директории OneDrive
$OneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
$IsOneDriveRunning = [bool]$OneDriveProcess
$OneDrivePath = "$env:USERPROFILE\OneDrive"
$HasOneDriveFolder = Test-Path $OneDrivePath

# Определение реального пути к Рабочему столу
$DesktopPath = [Environment]::GetFolderPath("Desktop")
if (-not $DesktopPath -or -not (Test-Path $DesktopPath)) {
    $DesktopPath = $PWD.Path
}

$OutputFile = Join-Path -Path $DesktopPath -ChildPath "Check_Result.txt"
$StartTime = Get-Date

function Generate-CheckerReport {
    Write-Output "==========================================================================="
    Write-Output "                       ОТЧЕТ ПРОВЕРКИ СИСТЕМЫ И СЛЕДОВ                     "
    Write-Output "==========================================================================="
    
    # --------------------------------------------------------------------------
    # 1. ПОИСК ИСПОЛНЯЕМЫХ ФАЙЛОВ И ТРАССИРОВКА (Cheat Execution / Traces)
    # --------------------------------------------------------------------------
    $TraceInDefender = $false
    $FoundExecutables = [System.Collections.Generic.List[string]]::new()

    # Сканирование целевых папок
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

    # Проверка Защитника
    $defService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if (-not $defService -or $defService.Status -ne "Running") {
        $TraceInDefender = $true
    }

    Write-Output "`n[!] РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ТРАССИРОВКИ:"
    if ($TraceInDefender) {
        Write-Output "[-] Обнаружены критические следы: Защитник Windows отключен или остановлен!"
    } else {
        Write-Output "[+] Служба Защитника Windows активна"
    }

    if ($FoundExecutables.Count -gt 0) {
        foreach ($exe in ($FoundExecutables | Select-Object -Unique)) {
            Write-Output "[-] Найден исполняемый файл читов/утилит: $exe"
        }
    } else {
        Write-Output "[+] Подозрительных standalone .exe в стандартных путях не обнаружено"
    }

    Write-Output ""
    Write-Output "-------------------"
    Write-Output "|      Система    |"
    Write-Output "-------------------"
    Write-Output ""

    # --------------------------------------------------------------------------
    # 2. МЕТРИКИ И ИНФОРМАЦИЯ О СИСТЕМЕ
    # --------------------------------------------------------------------------
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $bootTime = $os.LastBootUpTime
    $uptime = (Get-Date) - $bootTime

    Write-Output "Время запуска скрипта: $($StartTime.ToString('dd.MM.yyyy HH:mm:ss'))"
    
    $drives = (Get-PSDrive -PSProvider FileSystem).Root -join " "
    Write-Output "Подключенные диски: $drives"
    
    $regVolumes = (Get-ItemProperty -Path "HKLM:\SYSTEM\MountedDevices" -ErrorAction SilentlyContinue).PSObject.Properties | 
                  Where-Object { $_.Name -like "\DosDevices\*" } | 
                  ForEach-Object { $_.Name.Replace("\DosDevices\", "") }
    Write-Output "Тома в реестре: $($regVolumes -join ', ')"

    Write-Output "Версия Windows: $($os.Caption) (Сборка $($os.BuildNumber))"
    Write-Output "Дата установки Windows: $($os.InstallDate.ToString('dd.MM.yyyy'))"
    Write-Output "Время последней загрузки ПК: $($bootTime.ToString('dd.MM.yyyy HH:mm:ss'))"

    # Статус OneDrive
    Write-Output "`nСтатус OneDrive:"
    if ($IsOneDriveRunning) {
        Write-Output "  [!] Процесс OneDrive: АКТИВЕН"
    } else {
        Write-Output "  [+] Процесс OneDrive: НЕ АКТИВЕН"
    }

    if ($HasOneDriveFolder) {
        Write-Output "  [-] Папка OneDrive: Найдена ($OneDrivePath)"
    } else {
        Write-Output "  [+] Папка OneDrive: Отсутствует"
    }
    Write-Output "  [*] Целевой путь Рабочего стола: $DesktopPath"

    # Корзина
    $RecycleBin = Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($RecycleBin) {
        Write-Output "`nПоследняя активность Корзины: $($RecycleBin.LastWriteTime.ToString('dd.MM.yyyy HH:mm:ss'))"
    } else {
        Write-Output "`nПоследняя активность Корзины: Нет данных / Очищена"
    }

    # Установленное ПО
    Write-Output "`nПроверка подозрительного установленного ПО:"
    $Uninstalls = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", 
                                         "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                  Where-Object { $_.DisplayName -match "Process Hacker|System Informer|Cheat Engine|Process Explorer|Everything|Scylla|x64dbg" }
    
    if ($Uninstalls) {
        foreach ($app in $Uninstalls) {
            Write-Output ("  - {0,-35} Версия: {1}" -f $app.DisplayName, $app.DisplayVersion)
        }
    } else {
        Write-Output "  [+] Запрещенных программ анализа в реестре не найдено"
    }

    # Кэш DNS
    Write-Output "`nЗаписи локального DNS-кэша:"
    $dnsEntries = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -notmatch "local|microsoft|google|gta-five|discord|cloudflare" } | Select-Object -First 10
    if ($dnsEntries) {
        foreach ($dns in $dnsEntries) {
            Write-Output "  - Запись: $($dns.Entry) | Имя: $($dns.Name)"
        }
    } else {
        Write-Output "  [+] DNS-кэш чист"
    }

    # GTA V settings.xml
    Write-Output "`nПроверка отрицательных значений в settings.xml (GTA V):"
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
            Write-Output "    [+] Отрицательных параметров в settings.xml не обнаружено"
        }
    } else {
        Write-Output "    [!] Файл settings.xml не найден"
    }

    # Аптайм системных процессов
    Write-Output "`nВремя работы ключевых процессов (Process Uptime):"
    Write-Output "------------------------------------------------"
    $criticalProcesses = @("dnscache", "dwm", "explorer", "lsass", "PcaSvc", "sysmain", "WSearch", "DiagTrack", "DPS")
    foreach ($procName in $criticalProcesses) {
        $p = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($p) {
            $pUptime = (Get-Date) - $p.StartTime
            $pStr = "{0}д {1:D2}:{2:D2}:{3:D2}" -f $pUptime.Days, $pUptime.Hours, $pUptime.Minutes, $pUptime.Seconds
            Write-Output ("{0,-15} Аптайм: {1}" -f $procName, $pStr)
        } else {
            Write-Output ("{0,-15} СТАТУС: Остановлен / Не найден" -f $procName)
        }
    }

    Write-Output "`nОбщий аптайм системы: {0} Дней, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds

    # --------------------------------------------------------------------------
    # 3. ПОИСК УДАЛЕННЫХ EXECUTABLE ФАЙЛОВ (USN Journal Analysis)
    # --------------------------------------------------------------------------
    Write-Output ""
    Write-Output "------------------------------------------"
    Write-Output "| Сканирование удаленных файлов (USN)    |"
    Write-Output "------------------------------------------"
    Write-Output ""

    try {
        # Запрос записей удаления .exe из USN Журнала диска C:
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
            Write-Output "[!] Обнаружены недавно удаленные исполняемые файлы (.exe):"
            foreach ($delFile in $uniqueDeleted) {
                Write-Output "  [-] Удален файл: $delFile"
            }
        } else {
            Write-Output "[+] В журнале USN не найдено подозрительных удалений .exe файлов"
        }
    } catch {
        Write-Output "[!] Ошибка доступа к USN Журналу. Требуются права Администратора."
    }

    # --------------------------------------------------------------------------
    # 4. АНАЛИЗ ВМЕШАТЕЛЬСТВА (Tampering & Prefetch)
    # --------------------------------------------------------------------------
    Write-Output ""
    Write-Output "-------------------"
    Write-Output "|   Вмешательство |"
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
        Write-Output "[!] Ошибка целостности Prefetch (Отсутствуют ожидаемые записи: $($missingPF -join ', '))"
    } else {
        Write-Output "[+] Целостность Prefetch в норме"
    }

    # Подмена имени / Скрытые имена с пробелами
    $JournalUnicode = Get-ChildItem -Path "$env:LOCALAPPDATA\Temp", "C:\Windows\Prefetch" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\s{3,}" }
    if ($JournalUnicode) {
        foreach ($uFile in $JournalUnicode) {
            Write-Output "[-] Обнаружена маскировка символами/пробелами: $($uFile.FullName)"
        }
    } else {
        Write-Output "[+] Обфускация имен файлов в Temp/Prefetch не обнаружена"
    }

    # --------------------------------------------------------------------------
    # 5. АВТОЗАГРУЗКА И УГРОЗЫ
    # --------------------------------------------------------------------------
    Write-Output ""
    Write-Output "-------------------"
    Write-Output "|      Угрозы     |"
    Write-Output "-------------------"
    Write-Output ""

    Write-Output "Проверка автозагрузки в реестре (HKCU Run):"
    $RunKeys = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    if ($RunKeys) {
        foreach ($key in $RunKeys.psobject.Properties) {
            if ($key.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|Provider|Attach") {
                Write-Output "  - Запись автозапуска: $($key.Name) = $($key.Value)"
            }
        }
    }

    # --------------------------------------------------------------------------
    # 6. ЖУРНАЛЫ СОБЫТИЙ WINDOWS
    # --------------------------------------------------------------------------
    Write-Output ""
    Write-Output "-------------------"
    Write-Output "|     События     |"
    Write-Output "-------------------"
    Write-Output ""

    Write-Output "События срабатывания Защитника (Последние 5):"
    $defEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($defEvents) {
        foreach ($e in $defEvents) {
            Write-Output "  [$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] EventID: $($e.Id) | $($e.Message.Substring(0, [Math]::Min(80, $e.Message.Length)))"
        }
    } else {
        Write-Output "  [+] Свежих предупреждений Защитника не найдено"
    }

    Write-Output "`nСобытия установки/изменения служб (ID 7045/7040):"
    $svcEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045,7040} -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($svcEvents) {
        foreach ($se in $svcEvents) {
            Write-Output "  [$($se.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] EventID: $($se.Id) | $($se.Message.Substring(0, [Math]::Min(70, $se.Message.Length)))"
        }
    } else {
        Write-Output "  [+] Подозрительных изменений служб не зафиксировано"
    }

    Write-Output "`nВыполнение PowerShell скриптов (ID 4104):"
    $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 3 -ErrorAction SilentlyContinue
    if ($psEvents) {
        foreach ($pe in $psEvents) {
            Write-Output "  [$($pe.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] EventID: 4104 | Зафиксирован запуск скрипта"
        }
    } else {
        Write-Output "  [+] Журнал PowerShell чист или отключен"
    }

    Write-Output ""
    Write-Output "==========================================================================="
    Write-Output "                           КОНЕЦ ОТЧЕТА                                    "
    Write-Output "==========================================================================="
}

# --------------------------------------------------------------------------
# СОХРАНЕНИЕ В ФАЙЛ
# --------------------------------------------------------------------------
Generate-CheckerReport | Out-File -FilePath $OutputFile -Encoding utf8

Write-Host "`n[+] Проверка успешно завершена!" -ForegroundColor Green
Write-Host "[+] Отчет сохранен по пути: $OutputFile" -ForegroundColor Yellow
