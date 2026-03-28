#!/bin/bash
# ============================================================
#  NetGuard AI — Instalator (Linux / macOS / Raspberry Pi)
#  https://github.com/dragunarek/netguard
# ============================================================

set -e

NETGUARD_VERSION="1.0.0"
NETGUARD_DIR="$HOME/netguard"
VENV_DIR="$HOME/netguard-env"
REPO_URL="https://raw.githubusercontent.com/dragunarek/netguard/main"
PYTHON_MIN="3.9"

# Kolory
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo "  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo "  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo "  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo "  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo -e "${NC}"
    echo -e "  ${BLUE}Agent Sieci Domowej — wersja ${NETGUARD_VERSION}${NC}"
    echo -e "  ${CYAN}Instalator dla Linux / macOS / Raspberry Pi${NC}"
    echo ""
}

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
info() { echo -e "  ${BLUE}ℹ${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}▶ $1${NC}"; }

# ── Wykryj system operacyjny ─────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS="linux"
        DISTRO=$ID
    elif [[ -f /proc/device-tree/model ]] && grep -q "Raspberry" /proc/device-tree/model 2>/dev/null; then
        OS="linux"
        DISTRO="raspbian"
    else
        OS="linux"
        DISTRO="unknown"
    fi
}

# ── Sprawdź Python ───────────────────────────────────────────
check_python() {
    step "Sprawdzanie Python..."

    for cmd in python3 python; do
        if command -v $cmd &>/dev/null; then
            version=$($cmd -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
            major=$(echo $version | cut -d. -f1)
            minor=$(echo $version | cut -d. -f2)
            if [[ $major -ge 3 && $minor -ge 9 ]]; then
                PYTHON_CMD=$cmd
                ok "Python $version znaleziony ($cmd)"
                return
            fi
        fi
    done

    # Zainstaluj Python jeśli brak
    warn "Python $PYTHON_MIN+ nie znaleziony. Instaluję..."
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip python3-venv
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y python3 python3-pip
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm python python-pip
        else
            fail "Nie mogę zainstalować Python automatycznie. Zainstaluj ręcznie: https://python.org"
        fi
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install python3
        else
            fail "Zainstaluj Python z https://python.org lub Homebrew: brew install python3"
        fi
    fi
    PYTHON_CMD=python3
}

# ── Sprawdź uprawnienia root ─────────────────────────────────
check_root() {
    step "Sprawdzanie uprawnień..."
    if [[ $EUID -ne 0 ]]; then
        warn "Uruchomiono bez root. Niektóre funkcje (skanowanie ARP, blokowanie) wymagają sudo."
        warn "Zalecane uruchamianie: sudo bash install.sh"
        ROOT=false
    else
        ok "Uprawnienia root"
        ROOT=true
    fi
}

# ── Zainstaluj zależności systemowe ─────────────────────────
install_system_deps() {
    step "Instalowanie zależności systemowych..."

    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq
            sudo apt-get install -y \
                python3-venv python3-pip \
                nmap net-tools \
                avahi-utils samba-common-bin \
                iptables \
                2>/dev/null || true
            ok "Zależności APT zainstalowane"
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y python3-pip nmap net-tools 2>/dev/null || true
            ok "Zależności DNF zainstalowane"
        fi
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install nmap 2>/dev/null || true
            ok "Zależności Homebrew zainstalowane"
        else
            warn "Homebrew nie znaleziony. Pomiń lub zainstaluj: https://brew.sh"
        fi
    fi
}

# ── Utwórz katalog i virtualenv ──────────────────────────────
setup_venv() {
    step "Tworzenie środowiska Python..."

    mkdir -p "$NETGUARD_DIR"
    ok "Katalog $NETGUARD_DIR"

    if [[ ! -d "$VENV_DIR" ]]; then
        $PYTHON_CMD -m venv "$VENV_DIR"
        ok "Virtualenv w $VENV_DIR"
    else
        info "Virtualenv już istnieje — pomijam"
    fi

    # Aktywuj venv
    source "$VENV_DIR/bin/activate"

    # Aktualizuj pip
    pip install --upgrade pip --quiet
    ok "pip zaktualizowany"
}

# ── Zainstaluj zależności Python ─────────────────────────────
install_python_deps() {
    step "Instalowanie bibliotek Python..."

    pip install --quiet \
        scapy \
        psutil \
        flask \
        requests \
        colorama \
        ollama

    ok "scapy — analiza pakietów sieciowych"
    ok "psutil — monitoring systemu"
    ok "flask — web dashboard"
    ok "requests — HTTP client"
    ok "colorama — kolorowy terminal"
    ok "ollama — lokalny LLM (opcjonalny)"
}

# ── Pobierz pliki agenta ─────────────────────────────────────
download_files() {
    step "Pobieranie plików NetGuard..."

    # Jeśli uruchamiamy lokalnie (development) — kopiuj z bieżącego katalogu
    if [[ -f "$(dirname "$0")/netguard_agent.py" ]]; then
        cp "$(dirname "$0")/netguard_agent.py" "$NETGUARD_DIR/"
        cp "$(dirname "$0")/network-agent-dashboard.html" "$NETGUARD_DIR/" 2>/dev/null || true
        ok "Skopiowano lokalne pliki"
    else
        # Pobierz z GitHub
        curl -sSL "$REPO_URL/netguard_agent.py" -o "$NETGUARD_DIR/netguard_agent.py"
        curl -sSL "$REPO_URL/network-agent-dashboard.html" -o "$NETGUARD_DIR/network-agent-dashboard.html"
        ok "Pobrano z GitHub"
    fi
}

# ── Wizard konfiguracji ──────────────────────────────────────
run_wizard() {
    step "Konfiguracja NetGuard..."
    echo ""

    # Wykryj sieć
    if command -v ip &>/dev/null; then
        DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
        DEFAULT_NET=$(ip route show 2>/dev/null | grep -v default | grep "$DEFAULT_IFACE" | awk '{print $1}' | head -1)
    elif [[ "$OS" == "macos" ]]; then
        DEFAULT_IFACE=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
        DEFAULT_NET="192.168.1.0/24"
    fi

    DEFAULT_IFACE=${DEFAULT_IFACE:-"eth0"}
    DEFAULT_NET=${DEFAULT_NET:-"192.168.1.0/24"}

    echo -e "  Wykryto interfejs: ${CYAN}$DEFAULT_IFACE${NC}"
    echo -e "  Wykryto sieć:      ${CYAN}$DEFAULT_NET${NC}"
    echo ""

    # Email
    read -p "  Podaj adres email do powiadomień (Enter aby pominąć): " USER_EMAIL
    echo ""

    # Zapisz config do pliku
    cat > "$NETGUARD_DIR/.netguard.conf" << EOF
NETGUARD_INTERFACE=$DEFAULT_IFACE
NETGUARD_NETWORK=$DEFAULT_NET
NETGUARD_EMAIL=$USER_EMAIL
NETGUARD_PORT=8767
NETGUARD_VENV=$VENV_DIR
NETGUARD_DIR=$NETGUARD_DIR
EOF
    ok "Konfiguracja zapisana w $NETGUARD_DIR/.netguard.conf"
}

# ── Utwórz skrypt startowy ───────────────────────────────────
create_launcher() {
    step "Tworzenie skryptu startowego..."

    cat > "$NETGUARD_DIR/start.sh" << 'LAUNCHER'
#!/bin/bash
# NetGuard AI — skrypt startowy
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HOME/netguard-env"

if [[ $EUID -ne 0 ]]; then
    exec sudo bash "$0" "$@"
fi

source "$VENV/bin/activate"
cd "$SCRIPT_DIR"
exec python3 netguard_agent.py --dashboard "$@"
LAUNCHER

    chmod +x "$NETGUARD_DIR/start.sh"
    ok "start.sh"

    # Skrót .desktop dla Linux (menu aplikacji i pulpit)
    if [[ "$OS" == "linux" ]]; then
        DESKTOP_FILE="$HOME/.local/share/applications/netguard.desktop"
        mkdir -p "$HOME/.local/share/applications"
        cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=NetGuard AI
Comment=Lokalny agent monitorowania sieci domowej
Exec=bash -c 'sudo $NETGUARD_DIR/start.sh'
Icon=network-wired
Terminal=true
Type=Application
Categories=Network;Security;
Keywords=sieć;bezpieczeństwo;monitor;wifi;
EOF
        chmod +x "$DESKTOP_FILE"
        ok "Skrót w menu aplikacji (NetGuard AI)"

        # Skrót na pulpicie jeśli istnieje katalog Desktop
        for DESKTOP_DIR in "$HOME/Desktop" "$HOME/Pulpit" "$HOME/Biurko"; do
            if [[ -d "$DESKTOP_DIR" ]]; then
                cp "$DESKTOP_FILE" "$DESKTOP_DIR/netguard.desktop"
                chmod +x "$DESKTOP_DIR/netguard.desktop"
                ok "Skrót na pulpicie"
                break
            fi
        done
    fi
}

# ── Skonfiguruj systemd (autostart) ─────────────────────────
setup_systemd() {
    if [[ "$OS" != "linux" ]] || ! command -v systemctl &>/dev/null; then
        return
    fi

    step "Konfigurowanie autostartu (systemd)..."

    sudo tee /etc/systemd/system/netguard.service > /dev/null << EOF
[Unit]
Description=NetGuard AI — Agent Sieci Domowej
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$VENV_DIR/bin/python3 $NETGUARD_DIR/netguard_agent.py --dashboard
WorkingDirectory=$NETGUARD_DIR
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable netguard.service 2>/dev/null || true
    ok "Usługa systemd skonfigurowana"
    ok "NetGuard będzie startował automatycznie po restarcie"
}

# ── Launchd dla macOS ────────────────────────────────────────
setup_launchd() {
    if [[ "$OS" != "macos" ]]; then return; fi

    step "Konfigurowanie autostartu (launchd)..."

    PLIST="$HOME/Library/LaunchAgents/pl.netguard.agent.plist"
    cat > "$PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>pl.netguard.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$VENV_DIR/bin/python3</string>
        <string>$NETGUARD_DIR/netguard_agent.py</string>
        <string>--dashboard</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$NETGUARD_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/netguard/netguard.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/netguard/netguard-error.log</string>
</dict>
</plist>
EOF
    launchctl load "$PLIST" 2>/dev/null || true
    ok "Launchd skonfigurowany"
}

# ── Podsumowanie ─────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       NetGuard AI — instalacja zakończona!      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Jak uruchomić:${NC}"
    echo -e "  ${YELLOW}sudo bash $NETGUARD_DIR/start.sh${NC}"
    echo ""
    echo -e "  ${CYAN}Dashboard:${NC}"
    echo -e "  ${YELLOW}http://localhost:8767${NC}"
    echo ""
    if command -v systemctl &>/dev/null; then
        echo -e "  ${CYAN}Zarządzanie usługą:${NC}"
        echo -e "  ${YELLOW}sudo systemctl start netguard${NC}"
        echo -e "  ${YELLOW}sudo systemctl stop netguard${NC}"
        echo -e "  ${YELLOW}sudo systemctl status netguard${NC}"
        echo ""
    fi
    echo -e "  ${CYAN}Dokumentacja:${NC} https://github.com/dragunarek/netguard"
    echo ""
}

# ── GŁÓWNY FLOW ──────────────────────────────────────────────
main() {
    clear
    print_banner
    detect_os
    info "System: $OS ${DISTRO:-}"
    check_root
    check_python
    install_system_deps
    setup_venv
    install_python_deps
    download_files
    run_wizard
    create_launcher
    setup_systemd
    setup_launchd
    print_summary
}

main "$@"
