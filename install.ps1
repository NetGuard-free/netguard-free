# ============================================================
#  NetGuard AI — Instalator Windows (PowerShell)
#  Uruchom jako Administrator w PowerShell:
#  Set-ExecutionPolicy Bypass -Scope Process -Force
#  .\install.ps1
# ============================================================

$NETGUARD_VERSION = "1.0.0"
$NETGUARD_DIR = "$env:USERPROFILE\netguard"
$VENV_DIR = "$env:USERPROFILE\netguard-env"
$PYTHON_MIN = "3.9"
$REPO_URL = "https://raw.githubusercontent.com/dragunarek/netguard/main"

# Kolory
function Write-OK    { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Info  { param($msg) Write-Host "  [i]  $msg" -ForegroundColor Cyan }
function Write-Warn  { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "  [X]  $msg" -ForegroundColor Red; exit 1 }
function Write-Step  { param($msg) Write-Host "`n>> $msg" -ForegroundColor Magenta }

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ " -ForegroundColor Cyan
    Write-Host "  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗" -ForegroundColor Cyan
    Write-Host "  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║" -ForegroundColor Cyan
    Write-Host "  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║" -ForegroundColor Cyan
    Write-Host "  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝" -ForegroundColor Cyan
    Write-Host "  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Agent Sieci Domowej — wersja $NETGUARD_VERSION" -ForegroundColor Blue
    Write-Host "  Instalator dla Windows" -ForegroundColor Cyan
    Write-Host ""
}

# ── Sprawdź uprawnienia administratora ───────────────────────
function Check-Admin {
    Write-Step "Sprawdzanie uprawnień..."
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warn "Uruchom PowerShell jako Administrator dla pełnej funkcjonalności"
        Write-Warn "Kliknij prawym na PowerShell -> Uruchom jako administrator"
    } else {
        Write-OK "Uprawnienia administratora"
    }
}

# ── Sprawdź i zainstaluj Python ───────────────────────────────
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
        Write-Warn "Python 3.9+ nie znaleziony. Próbuję zainstalować przez winget..."
        try {
            winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
            Write-OK "Python zainstalowany przez winget"
            # Odśwież PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
            $pythonCmd = "python"
        } catch {
            Write-Fail "Nie mogę zainstalować Python automatycznie.`n  Pobierz ręcznie: https://python.org/downloads`n  Zaznacz 'Add Python to PATH' podczas instalacji!"
        }
    }

    return $pythonCmd
}

# ── Utwórz katalog i virtualenv ───────────────────────────────
function Setup-Venv {
    param($PythonCmd)
    Write-Step "Tworzenie środowiska Python..."

    New-Item -ItemType Directory -Force -Path $NETGUARD_DIR | Out-Null
    Write-OK "Katalog $NETGUARD_DIR"

    if (-not (Test-Path $VENV_DIR)) {
        & $PythonCmd -m venv $VENV_DIR
        Write-OK "Virtualenv w $VENV_DIR"
    } else {
        Write-Info "Virtualenv już istnieje — pomijam"
    }

    # Aktualizuj pip
    & "$VENV_DIR\Scripts\python.exe" -m pip install --upgrade pip --quiet
    Write-OK "pip zaktualizowany"
}

# ── Zainstaluj zależności Python ──────────────────────────────
function Install-PythonDeps {
    Write-Step "Instalowanie bibliotek Python..."

    $packages = @("scapy", "psutil", "flask", "requests", "colorama", "ollama")
    foreach ($pkg in $packages) {
        & "$VENV_DIR\Scripts\pip.exe" install $pkg --quiet
        Write-OK "$pkg"
    }
}

# ── Pobierz pliki agenta ──────────────────────────────────────
function Download-Files {
    Write-Step "Pobieranie plików NetGuard..."

    $localAgent = Join-Path (Split-Path $MyInvocation.ScriptName) "netguard_agent.py"
    if (Test-Path $localAgent) {
        Copy-Item $localAgent "$NETGUARD_DIR\netguard_agent.py" -Force
        $localDash = Join-Path (Split-Path $MyInvocation.ScriptName) "network-agent-dashboard.html"
        if (Test-Path $localDash) {
            Copy-Item $localDash "$NETGUARD_DIR\network-agent-dashboard.html" -Force
        }
        Write-OK "Skopiowano lokalne pliki"
    } else {
        try {
            Invoke-WebRequest -Uri "$REPO_URL/netguard_agent.py" -OutFile "$NETGUARD_DIR\netguard_agent.py" -UseBasicParsing
            Invoke-WebRequest -Uri "$REPO_URL/network-agent-dashboard.html" -OutFile "$NETGUARD_DIR\network-agent-dashboard.html" -UseBasicParsing
            Write-OK "Pobrano z GitHub"
        } catch {
            Write-Fail "Nie mogę pobrać plików: $_"
        }
    }
}

# ── Wizard konfiguracji ───────────────────────────────────────
function Run-Wizard {
    Write-Step "Konfiguracja NetGuard..."
    Write-Host ""

    # Wykryj interfejs sieciowy
    $defaultIface = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
    $defaultNet = "192.168.1.0/24"
    try {
        $ip = (Get-NetIPAddress -InterfaceAlias $defaultIface -AddressFamily IPv4 | Select-Object -First 1).IPAddress
        $prefix = (Get-NetIPAddress -InterfaceAlias $defaultIface -AddressFamily IPv4 | Select-Object -First 1).PrefixLength
        # Uproszczone obliczenie sieci
        $ipParts = $ip -split "\."
        $defaultNet = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).0/$prefix"
    } catch {}

    Write-Host "  Wykryto interfejs: $defaultIface" -ForegroundColor Cyan
    Write-Host "  Wykryto sieć:      $defaultNet" -ForegroundColor Cyan
    Write-Host ""

    $userEmail = Read-Host "  Podaj adres email do powiadomień (Enter aby pominąć)"
    Write-Host ""

    # Zapisz config
    @"
NETGUARD_INTERFACE=$defaultIface
NETGUARD_NETWORK=$defaultNet
NETGUARD_EMAIL=$userEmail
NETGUARD_PORT=8767
NETGUARD_VENV=$VENV_DIR
NETGUARD_DIR=$NETGUARD_DIR
"@ | Set-Content "$NETGUARD_DIR\.netguard.conf"

    Write-OK "Konfiguracja zapisana"

    return @{
        Interface = $defaultIface
        Network   = $defaultNet
        Email     = $userEmail
    }
}

# ── Utwórz skrypt startowy ────────────────────────────────────
function Create-Launcher {
    Write-Step "Tworzenie skryptów startowych..."

    # start.bat — dla zwykłego uruchamiania
    @"
@echo off
echo Uruchamianie NetGuard AI...
cd /d "%USERPROFILE%\netguard"
"%USERPROFILE%\netguard-env\Scripts\python.exe" netguard_agent.py --dashboard
pause
"@ | Set-Content "$NETGUARD_DIR\start.bat"

    # start-admin.bat — uruchom jako administrator
    @"
@echo off
powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %USERPROFILE%\netguard && %USERPROFILE%\netguard-env\Scripts\python.exe netguard_agent.py --dashboard && pause' -Verb RunAs"
"@ | Set-Content "$NETGUARD_DIR\start-admin.bat"

    Write-OK "start.bat — zwykłe uruchomienie"
    Write-OK "start-admin.bat — uruchomienie jako administrator (zalecane)"

    # Skrót na pulpicie
    try {
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\NetGuard AI.lnk")
        $Shortcut.TargetPath = "$NETGUARD_DIR\start-admin.bat"
        $Shortcut.WorkingDirectory = $NETGUARD_DIR
        $Shortcut.Description = "NetGuard AI — Agent Sieci Domowej"
        $Shortcut.Save()
        Write-OK "Skrót na pulpicie"
    } catch {
        Write-Warn "Nie mogę utworzyć skrótu na pulpicie"
    }
}

# ── Skonfiguruj Task Scheduler (autostart) ────────────────────
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
            -TaskName "NetGuard AI" `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal `
            -Description "NetGuard AI — Agent monitorowania sieci domowej" `
            -Force | Out-Null

        Write-OK "Task Scheduler skonfigurowany — NetGuard startuje przy logowaniu"
    } catch {
        Write-Warn "Nie mogę skonfigurować Task Scheduler: $_"
        Write-Info "Uruchamiaj ręcznie przez start-admin.bat"
    }
}

# ── Podsumowanie ──────────────────────────────────────────────
function Print-Summary {
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║       NetGuard AI — instalacja zakończona!      ║" -ForegroundColor Green
    Write-Host "  ╚════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Jak uruchomić:" -ForegroundColor Cyan
    Write-Host "  Kliknij dwukrotnie: NetGuard AI (skrót na pulpicie)" -ForegroundColor Yellow
    Write-Host "  lub uruchom: $NETGUARD_DIR\start-admin.bat" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Dashboard (po uruchomieniu):" -ForegroundColor Cyan
    Write-Host "  http://localhost:8767" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  WAŻNE dla Windows:" -ForegroundColor Cyan
    Write-Host "  Skanowanie ARP wymaga Npcap: https://npcap.com/#download" -ForegroundColor Yellow
    Write-Host "  (darmowy, instaluj z opcją 'WinPcap API compatible mode')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Dokumentacja: https://github.com/dragunarek/netguard" -ForegroundColor Cyan
    Write-Host ""
}

# ── GŁÓWNY FLOW ───────────────────────────────────────────────
Write-Banner
Check-Admin
$pythonCmd = Check-Python
Setup-Venv -PythonCmd $pythonCmd
Install-PythonDeps
Download-Files
$config = Run-Wizard
Create-Launcher
Setup-TaskScheduler
Print-Summary
