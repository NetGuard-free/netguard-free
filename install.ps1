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
$REPO_URL = "https://raw.githubusercontent.com/NetGuard-free/netguard-free/main"

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

# ── Zainstaluj Npcap (wymagany przez Scapy do skanowania ARP) ─
function Install-Npcap {
    Write-Step "Sprawdzanie Npcap..."

    # Sprawdź czy już zainstalowany
    $installed = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Npcap" -ErrorAction SilentlyContinue
    if ($installed) {
        Write-OK "Npcap już zainstalowany"
        return
    }

    Write-Info "Pobieranie Npcap (wymagany do skanowania sieci ARP)..."

    $npcapUrl       = "https://npcap.com/dist/npcap-1.82.exe"
    $npcapInstaller = "$env:TEMP\npcap-installer.exe"

    try {
        Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller -UseBasicParsing
        Write-Host ""
        Write-Host "  *** WAŻNE — przeczytaj przed kliknięciem Next! ***" -ForegroundColor Yellow
        Write-Host "  W instalatorze Npcap zaznacz opcję:" -ForegroundColor Yellow
        Write-Host "  [x] Install Npcap in WinPcap API-compatible Mode" -ForegroundColor Cyan
        Write-Host "  Bez tej opcji skanowanie sieci nie będzie działać." -ForegroundColor Yellow
        Write-Host ""
        Read-Host "  Naciśnij Enter aby otworzyć instalator Npcap..."
        Start-Process -FilePath $npcapInstaller -Wait
        Remove-Item $npcapInstaller -Force -ErrorAction SilentlyContinue
        Write-OK "Npcap zainstalowany"
    } catch {
        Write-Warn "Nie mogę pobrać Npcap automatycznie."
        Write-Warn "Pobierz ręcznie: https://npcap.com/#download"
        Write-Warn "Zaznacz 'WinPcap API compatible mode' podczas instalacji!"
    }
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

    $scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { "" }
    $localAgent = if ($scriptDir) { Join-Path $scriptDir "netguard_agent.py" } else { "" }
    if ($localAgent -and (Test-Path $localAgent)) {
        Copy-Item $localAgent "$NETGUARD_DIR\netguard_agent.py" -Force
        $localDash = Join-Path $scriptDir "network-agent-dashboard.html"
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

# ── Wizard konfiguracji — tworzy config.json ─────────────────
function Run-Wizard {
    Write-Step "Konfiguracja NetGuard..."
    Write-Host ""

    # Wykryj interfejs i sieć przez PowerShell (działa na Windows)
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

    Write-Host "  Wykryto sieć: $defaultNet" -ForegroundColor Cyan
    Write-Host ""

    $userEmail = Read-Host "  Podaj adres email do powiadomień (Enter aby pominąć)"
    Write-Host ""

    # Hasło admina dashboardu — hash SHA-256 w PowerShell
    Write-Host "  Ustaw hasło do panelu admina:" -ForegroundColor Cyan
    do {
        $pwd1 = Read-Host "  Hasło" -AsSecureString
        $pwd2 = Read-Host "  Powtórz hasło" -AsSecureString
        $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1))
        $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2))
        if ($plain1 -ne $plain2) { Write-Warn "Hasła nie są identyczne. Spróbuj ponownie." }
    } while ($plain1 -ne $plain2)

    $sha256    = [System.Security.Cryptography.SHA256]::Create()
    $pwdHash   = [BitConverter]::ToString($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($plain1))).Replace("-","").ToLower()

    # Utwórz config.json (format wymagany przez agenta)
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

    # Utwórz pusty netguard_devices.json
    if (-not (Test-Path "$NETGUARD_DIR\netguard_devices.json")) {
        @{ trusted_macs = @(); blocked_macs = @(); device_names = @{} } `
            | ConvertTo-Json | Set-Content "$NETGUARD_DIR\netguard_devices.json" -Encoding UTF8
    }

    Write-OK "Konfiguracja zapisana (config.json)"

    return @{ Network = $defaultNet; Email = $userEmail }
}

# ── Utwórz skrypt startowy ────────────────────────────────────
function Create-Launcher {
    Write-Step "Tworzenie skryptów startowych..."

    # start.bat — uruchamia agenta z dashboardem, pause trzyma okno przy błędzie
    @"
@echo off
title NetGuard AI
cd /d "%USERPROFILE%\netguard"
echo  Uruchamianie NetGuard AI...
echo  Dashboard bedzie dostepny pod: http://localhost:8767
echo.
"%USERPROFILE%\netguard-env\Scripts\python.exe" netguard_agent.py --dashboard
echo.
echo  NetGuard zakonczyl dzialanie.
pause
"@ | Set-Content "$NETGUARD_DIR\start.bat" -Encoding ASCII

    Write-OK "start.bat utworzony"

    # Otwórz port 8767 w Windows Firewall
    try {
        $ruleName = "NetGuard Dashboard (port 8767)"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound -Protocol TCP -LocalPort 8767 `
                -Action Allow -Profile Any | Out-Null
            Write-OK "Port 8767 otwarty w Windows Firewall"
        } else {
            Write-Info "Reguła firewall już istnieje"
        }
    } catch {
        Write-Warn "Nie mogę dodać reguły firewall — uruchom ponownie jako Administrator"
    }

    # Skrót na pulpicie — target: start.bat, flaga "Run as Administrator"
    try {
        $lnkPath = "$env:USERPROFILE\Desktop\NetGuard AI.lnk"
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($lnkPath)
        $Shortcut.TargetPath       = "$NETGUARD_DIR\start.bat"
        $Shortcut.WorkingDirectory = $NETGUARD_DIR
        $Shortcut.Description      = "NetGuard AI — Agent Sieci Domowej"
        $Shortcut.Save()
        # Ustaw flagę "Uruchom jako administrator" w pliku .lnk (bajt 0x15, bit 0x20)
        $bytes = [System.IO.File]::ReadAllBytes($lnkPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($lnkPath, $bytes)
        Write-OK "Skrót na pulpicie (z uprawnieniami administratora)"
    } catch {
        Write-Warn "Nie mogę utworzyć skrótu na pulpicie: $_"
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
    Write-Host "  Dokumentacja: https://github.com/NetGuard-free/netguard-free" -ForegroundColor Cyan
    Write-Host ""
}

# ── GŁÓWNY FLOW ───────────────────────────────────────────────
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
