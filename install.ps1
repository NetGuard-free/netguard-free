# ============================================================
#  NetGuard - Instalator Windows (PowerShell)
#  Wersja modułowa (Free Edition)
#  Uruchom jako Administrator w PowerShell:
#  Set-ExecutionPolicy Bypass -Scope Process -Force
#  .\install.ps1
# ============================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8
try { chcp 65001 | Out-Null } catch {}

$NETGUARD_VERSION = "1.5.0"
$NETGUARD_DIR = "$env:USERPROFILE\netguard"
$VENV_DIR = "$env:USERPROFILE\netguard-env"
$PYTHON_MIN = "3.9"
$PKG_URL = "https://raw.githubusercontent.com/NetGuard-free/netguard-free/main/netguard-v1.5.0.zip"

function Write-OK    { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Info  { param($msg) Write-Host "  [i]  $msg" -ForegroundColor Cyan }
function Write-Warn  { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "  [X]  $msg" -ForegroundColor Red; exit 1 }
function Write-Step  { param($msg) Write-Host "`n>> $msg" -ForegroundColor Magenta }

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |        N E T G U A R D                          |" -ForegroundColor Cyan
    Write-Host "  |        Agent Sieci Domowej  v$NETGUARD_VERSION              |" -ForegroundColor Cyan
    Write-Host "  |        Instalator Windows (modułowy)             |" -ForegroundColor Cyan
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Check-Admin {
    Write-Step "Sprawdzanie uprawnien..."
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warn "Uruchom PowerShell jako Administrator dla pelnej funkcjonalnosci"
        Write-Warn "Kliknij prawym na PowerShell -> Uruchom jako administrator"
    } else {
        Write-OK "Uprawnienia administratora"
    }
}

function Check-Python {
    Write-Step "Sprawdzanie Python..."

    $pythonCmd = $null
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python (\d+)\.(\d+)") {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                if ($major -ge 3 -and $minor -ge 9) {
                    $pythonCmd = $cmd
                    Write-OK "Python $major.$minor znaleziony ($cmd)"
                    break
                }
            }
        } catch {}
    }

    if (-not $pythonCmd) {
        Write-Warn "Python 3.9+ nie znaleziony. Probuje zainstalowac przez winget..."
        try {
            winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
            Write-OK "Python zainstalowany przez winget"
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
            $pythonCmd = "python"
        } catch {
            Write-Fail "Nie moge zainstalowac Python automatycznie.`n  Pobierz recznie: https://python.org/downloads`n  Zaznacz 'Add Python to PATH' podczas instalacji!"
        }
    }

    return $pythonCmd
}

function Setup-Venv {
    param($PythonCmd)
    Write-Step "Tworzenie srodowiska Python..."

    New-Item -ItemType Directory -Force -Path $NETGUARD_DIR | Out-Null
    Write-OK "Katalog $NETGUARD_DIR"

    if (-not (Test-Path $VENV_DIR)) {
        & $PythonCmd -m venv $VENV_DIR
        Write-OK "Virtualenv w $VENV_DIR"
    } else {
        Write-Info "Virtualenv juz istnieje - pomijam"
    }

    & "$VENV_DIR\Scripts\python.exe" -m pip install --upgrade pip --quiet
    Write-OK "pip zaktualizowany"
}

function Install-Npcap {
    Write-Step "Sprawdzanie Npcap..."

    $installed = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Npcap" -ErrorAction SilentlyContinue
    if ($installed) {
        Write-OK "Npcap juz zainstalowany"
        return
    }

    Write-Info "Pobieranie Npcap (wymagany do skanowania sieci ARP)..."

    $npcapUrl       = "https://npcap.com/dist/npcap-1.82.exe"
    $npcapInstaller = "$env:TEMP\npcap-installer.exe"

    try {
        Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller -UseBasicParsing
        Write-Host ""
        Write-Host "  *** WAZNE - przeczytaj przed kliknieciem Next! ***" -ForegroundColor Yellow
        Write-Host "  W instalatorze Npcap zaznacz opcje:" -ForegroundColor Yellow
        Write-Host "  [x] Install Npcap in WinPcap API-compatible Mode" -ForegroundColor Cyan
        Write-Host ""
        Read-Host "  Nacisnij Enter aby otworzyc instalator Npcap..."
        Start-Process -FilePath $npcapInstaller -Wait
        Remove-Item $npcapInstaller -Force -ErrorAction SilentlyContinue
        Write-OK "Npcap zainstalowany"
    } catch {
        Write-Warn "Nie moge pobrac Npcap automatycznie."
        Write-Warn "Pobierz recznie: https://npcap.com/#download"
        Write-Warn "Zaznacz 'WinPcap API compatible mode' podczas instalacji!"
    }
}

function Install-PythonDeps {
    Write-Step "Instalowanie bibliotek Python..."

    $packages = @("scapy", "psutil", "flask", "requests", "colorama", "ollama")
    foreach ($pkg in $packages) {
        & "$VENV_DIR\Scripts\pip.exe" install $pkg --quiet
        Write-OK "$pkg"
    }
}

function Download-Files {
    Write-Step "Pobieranie plikow NetGuard..."

    $scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { "" }
    $localAgent = if ($scriptDir) { Join-Path $scriptDir "netguard_agent.py" } else { "" }
    $localPkg   = if ($scriptDir) { Join-Path $scriptDir "netguard" } else { "" }
    if ($localAgent -and (Test-Path $localAgent) -and $localPkg -and (Test-Path $localPkg)) {
        Copy-Item $localAgent "$NETGUARD_DIR\netguard_agent.py" -Force
        Copy-Item -Recurse $localPkg "$NETGUARD_DIR\netguard" -Force
        $localDash = Join-Path $scriptDir "network-agent-dashboard.html"
        if (Test-Path $localDash) {
            Copy-Item $localDash "$NETGUARD_DIR\network-agent-dashboard.html" -Force
        }
        Write-OK "Skopiowano lokalne pliki modułowe"
    } else {
        try {
            $zipFile = "$env:TEMP\netguard-v1.5.0.zip"
            Write-Info "Pobieranie NetGuard v1.5.0 (modułowy)..."
            Invoke-WebRequest -Uri $PKG_URL -OutFile $zipFile -UseBasicParsing
            if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
                Expand-Archive -Path $zipFile -DestinationPath "$env:TEMP\netguard-pkg" -Force
                $pkgRoot = "$env:TEMP\netguard-pkg"
                $subdirs = Get-ChildItem -Path $pkgRoot -Directory
                if ($subdirs.Count -eq 1) {
                    # zip ma jeden katalog nadrzedny (np. netguard-free/) — wyciagnij jego zawartosc
                    Move-Item "$($subdirs[0].FullName)\*" $NETGUARD_DIR\ -Force
                } else {
                    Move-Item "$pkgRoot\*" $NETGUARD_DIR\ -Force
                }
                Remove-Item "$env:TEMP\netguard-pkg" -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $zip = [System.IO.Compression.ZipFile]::OpenRead($zipFile)
                $dest = "$env:TEMP\netguard-pkg"
                $zip.Entries | ForEach-Object {
                    $target = Join-Path $dest $_.FullName
                    $dir = Split-Path $target -Parent
                    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
                    if ($_.Name) { [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $target, $true) }
                }
                $zip.Dispose()
                $subdirs = Get-ChildItem -Path $dest -Directory
                if ($subdirs.Count -eq 1) {
                    Move-Item "$($subdirs[0].FullName)\*" $NETGUARD_DIR\ -Force
                } else {
                    Move-Item "$dest\*" $NETGUARD_DIR\ -Force
                }
                Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
            }
            Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
            Write-OK "Pobrano modułowy pakiet z GitHub"
        } catch {
            Write-Fail "Nie moge pobrac plikow: $_"
        }
    }
}

function Run-Wizard {
    Write-Step "Konfiguracja NetGuard..."
    Write-Host ""

    $defaultIface = "auto"
    $defaultNet   = "192.168.1.0/24"
    try {
        $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1
        $iface = $route.InterfaceAlias
        $ipObj = Get-NetIPAddress -InterfaceAlias $iface -AddressFamily IPv4 | Select-Object -First 1
        if ($ipObj) {
            $ipParts    = $ipObj.IPAddress -split "\."
            $defaultNet = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).0/$($ipObj.PrefixLength)"
        }
    } catch {}

    Write-Host "  Wykryto siec: $defaultNet" -ForegroundColor Cyan
    Write-Host ""

    $userEmail = Read-Host "  Podaj adres email do powiadomien (Enter aby pominac)"
    Write-Host ""

    Write-Host "  Ustaw haslo do panelu admina:" -ForegroundColor Cyan
    do {
        $pwd1 = Read-Host "  Haslo" -AsSecureString
        $pwd2 = Read-Host "  Powtorz haslo" -AsSecureString
        $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1))
        $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2))
        if ($plain1 -ne $plain2) { Write-Warn "Hasla nie sa identyczne. Sprobuj ponownie." }
    } while ($plain1 -ne $plain2)

    $sha256    = [System.Security.Cryptography.SHA256]::Create()
    $pwdHash   = [BitConverter]::ToString($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($plain1))).Replace("-","").ToLower()

    $config = @{
        network_range       = $defaultNet
        interface           = "auto"
        alert_email         = $userEmail
        dashboard_port      = 8767
        admin_password_hash = $pwdHash
        smtp = @{
            host     = "smtp.gmail.com"
            port     = 587
            user     = $userEmail
            password = ""
        }
    }
    $config | ConvertTo-Json -Depth 5 | Set-Content "$NETGUARD_DIR\config.json" -Encoding UTF8

    if (-not (Test-Path "$NETGUARD_DIR\netguard_devices.json")) {
        @{ trusted_macs = @(); blocked_macs = @(); device_names = @{} } `
            | ConvertTo-Json | Set-Content "$NETGUARD_DIR\netguard_devices.json" -Encoding UTF8
    }

    Write-OK "Konfiguracja zapisana (config.json)"

    return @{ Network = $defaultNet; Email = $userEmail }
}

function Create-Launcher {
    Write-Step "Tworzenie skryptow startowych..."

    @"
@echo off
title NetGuard
cd /d "%USERPROFILE%\netguard"
echo  Uruchamianie NetGuard...
echo  Dashboard bedzie dostepny pod: http://localhost:8767
echo.
"%USERPROFILE%\netguard-env\Scripts\python.exe" netguard_agent.py --dashboard
echo.
echo  NetGuard zakonczyl dzialanie.
pause
"@ | Set-Content "$NETGUARD_DIR\start.bat" -Encoding ASCII

    Write-OK "start.bat utworzony"

    try {
        $ruleName = "NetGuard Dashboard (port 8767)"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound -Protocol TCP -LocalPort 8767 `
                -Action Allow -Profile Any | Out-Null
            Write-OK "Port 8767 otwarty w Windows Firewall"
        } else {
            Write-Info "Regula firewall juz istnieje"
        }
    } catch {
        Write-Warn "Nie moge dodac reguly firewall - uruchom ponownie jako Administrator"
    }

    try {
        $lnkPath = "$env:USERPROFILE\Desktop\NetGuard.lnk"
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($lnkPath)
        $Shortcut.TargetPath       = "$NETGUARD_DIR\start.bat"
        $Shortcut.WorkingDirectory = $NETGUARD_DIR
        $Shortcut.Description      = "NetGuard - Agent Sieci Domowej"
        $Shortcut.IconLocation     = "$NETGUARD_DIR\netguard.ico, 0"
        $Shortcut.Save()
        $bytes = [System.IO.File]::ReadAllBytes($lnkPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($lnkPath, $bytes)
        Write-OK "Skrot na pulpicie (z uprawnieniami administratora)"
    } catch {
        Write-Warn "Nie moge utworzyc skrotu na pulpicie: $_"
    }
}

function Setup-TaskScheduler {
    Write-Step "Konfigurowanie autostartu (Task Scheduler)..."

    try {
        $action = New-ScheduledTaskAction `
            -Execute "$VENV_DIR\Scripts\python.exe" `
            -Argument "netguard_agent.py --dashboard" `
            -WorkingDirectory $NETGUARD_DIR

        $trigger = New-ScheduledTaskTrigger -AtLogOn

        $settings = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit 0 `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1)

        $principal = New-ScheduledTaskPrincipal `
            -UserId $env:USERNAME `
            -RunLevel Highest

        Register-ScheduledTask `
            -TaskName "NetGuard" `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal `
            -Description "NetGuard - Agent monitorowania sieci domowej" `
            -Force | Out-Null

        Write-OK "Task Scheduler skonfigurowany - NetGuard startuje przy logowaniu"
    } catch {
        Write-Warn "Nie moge skonfigurowac Task Scheduler: $_"
        Write-Info "Uruchamiaj recznie przez start.bat"
    }
}

function Print-Summary {
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║       NetGuard - instalacja zakonczona!      ║" -ForegroundColor Green
    Write-Host "  ╚════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Jak uruchomic:" -ForegroundColor Cyan
    Write-Host "  Kliknij dwukrotnie: NetGuard (skrot na pulpicie)" -ForegroundColor Yellow
    Write-Host "  lub uruchom: $NETGUARD_DIR\start.bat" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Dashboard (po uruchomieniu):" -ForegroundColor Cyan
    Write-Host "  http://localhost:8767" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Dokumentacja: https://github.com/NetGuard-free/netguard-free" -ForegroundColor Cyan
    Write-Host ""
}

Write-Banner
Check-Admin
Install-Npcap
$pythonCmd = Check-Python
Setup-Venv -PythonCmd $pythonCmd
Install-PythonDeps
Download-Files
$config = Run-Wizard
Create-Launcher
Setup-TaskScheduler
Print-Summary
