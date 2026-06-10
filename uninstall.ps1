# ============================================================
#  NetGuard — Dezinstalator Windows (PowerShell)
#  Uruchom jako Administrator w PowerShell:
#  Set-ExecutionPolicy Bypass -Scope Process -Force
#  .\uninstall.ps1
# ============================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try { chcp 65001 | Out-Null } catch {}

$NETGUARD_DIR  = "$env:USERPROFILE\netguard"
$VENV_DIR      = "$env:USERPROFILE\netguard-env"
$LNK_PATH      = "$env:USERPROFILE\Desktop\NetGuard.lnk"
$TASK_NAME     = "NetGuard"
$FW_RULE_NAME  = "NetGuard Dashboard (port 8767)"

function Write-OK    { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Info  { param($msg) Write-Host "  [i]  $msg" -ForegroundColor Cyan }
function Write-Warn  { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }

Clear-Host
Write-Host ""
Write-Host "  +--------------------------------------------------+" -ForegroundColor Red
Write-Host "  |        N E T G U A R D   —   D E Z I N S T A L A C J A    |" -ForegroundColor Red
Write-Host "  +--------------------------------------------------+" -ForegroundColor Red
Write-Host ""

# Sprawdzanie uprawnien administratora
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Uruchom PowerShell jako Administrator (prawym przyciskiem -> Uruchom jako administrator)"
    exit 1
}

$confirmed = Read-Host "Usunac NetGuard wraz ze wszystkimi danymi? (tak/nie)"
if ($confirmed -ne "tak") {
    Write-Info "Anulowano."
    exit 0
}
Write-Host ""

# 1. Zatrzymanie dzialajacego agenta
Write-Host ">> Zatrzymywanie NetGuard..." -ForegroundColor Magenta
Get-WmiObject Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "netguard_agent"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
Write-OK "Procesy zakonczone"

# 2. Usuniecie Task Scheduler
Write-Host ">> Usuwanie zadania z Task Scheduler..." -ForegroundColor Magenta
try {
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    Write-OK "Zadanie '$TASK_NAME' usuniete"
} catch {
    Write-Info "Zadanie '$TASK_NAME' nie istnieje"
}

# 3. Usuniecie reguly firewall
Write-Host ">> Usuwanie reguly firewall..." -ForegroundColor Magenta
try {
    netsh advfirewall firewall delete rule name="$FW_RULE_NAME" | Out-Null
    Write-OK "Regula firewall usunieta"
} catch {
    Write-Info "Regula firewall nie istnieje"
}

# 4. Usuniecie skrotu z pulpitu
Write-Host ">> Usuwanie skrotu z pulpitu..." -ForegroundColor Magenta
if (Test-Path $LNK_PATH) {
    Remove-Item $LNK_PATH -Force
    Write-OK "Skrot usuniety"
} else {
    Write-Info "Skrot nie istnieje"
}

# 5. Usuniecie katalogu instalacyjnego
Write-Host ">> Usuwanie katalogu NetGuard..." -ForegroundColor Magenta
if (Test-Path $NETGUARD_DIR) {
    Remove-Item $NETGUARD_DIR -Recurse -Force
    Write-OK "Katalog '$NETGUARD_DIR' usuniety"
} else {
    Write-Info "Katalog '$NETGUARD_DIR' nie istnieje"
}

# 6. Usuniecie virtualenva
Write-Host ">> Usuwanie srodowiska Python..." -ForegroundColor Magenta
if (Test-Path $VENV_DIR) {
    Remove-Item $VENV_DIR -Recurse -Force
    Write-OK "Srodowisko '$VENV_DIR' usuniete"
} else {
    Write-Info "Srodowisko '$VENV_DIR' nie istnieje"
}

# 7. Npcap — opcjonalnie
Write-Host ""
Write-Host ">> Npcap (wymagany do skanowania ARP) nie zostal usuniety." -ForegroundColor Yellow
Write-Host "   Odinstaluj recznie przez: Ustawienia -> Aplikacje -> Npcap" -ForegroundColor Yellow
Write-Host ""
Write-Host "  +--------------------------------------------------+" -ForegroundColor Green
Write-Host "  |        NetGuard — calkowicie usuniety!            |" -ForegroundColor Green
Write-Host "  +--------------------------------------------------+" -ForegroundColor Green
Write-Host ""
