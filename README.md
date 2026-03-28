# 🛡 NetGuard AI — Agent Sieci Domowej

> Lokalny agent AI który monitoruje Twoją sieć domową, wykrywa zagrożenia i codziennie wysyła raport. Zero chmury. 100% prywatności.

![NetGuard Dashboard](https://raw.githubusercontent.com/dragunarek/netguard/main/docs/screenshot.png)

---

## Co robi NetGuard?

- 🔍 **Wykrywa urządzenia** — skanuje sieć co minutę i powiadamia o nowych, nieznanych urządzeniach
- 🚨 **Wykrywa zagrożenia** — ARP Spoofing, DNS Tunneling, Port Scanning, anomalie IoT (Tuya, smart home)
- 📧 **Codziennie raport** — o 20:00 wysyła email z podsumowaniem dnia
- 🤖 **Lokalny LLM** — pyta agenta AI o analizę sieci w języku polskim (przez Ollama, bez chmury)
- 🔒 **100% lokalnie** — żadne dane nie opuszczają Twojej sieci

---

## Szybka instalacja

### Linux / Raspberry Pi / macOS
```bash
curl -sSL https://raw.githubusercontent.com/dragunarek/netguard/main/install.sh | sudo bash
```

### Windows (PowerShell jako Administrator)
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
irm https://raw.githubusercontent.com/dragunarek/netguard/main/install.ps1 | iex
```

### Docker
```bash
docker run -d --name netguard --network host --cap-add NET_ADMIN \
  -e NETGUARD_EMAIL=twoj@email.com \
  dragunarek/netguard:latest
```

Po instalacji otwórz: **http://localhost:8767**

---

## Wymagania

| System | Wymagania |
|---|---|
| Linux / RPi | Python 3.9+, root/sudo |
| macOS | Python 3.9+, Homebrew (opcjonalny) |
| Windows | Python 3.9+, **[Npcap](https://npcap.com/#download)** (wymagany do skanowania ARP) |

**Opcjonalnie:** [Ollama](https://ollama.com) + model `llama3.2` dla funkcji AI

---

## Co wykrywa?

| Zagrożenie | Opis | Poziom |
|---|---|---|
| 🆕 Nowe urządzenie | Nieznany MAC w sieci | HIGH |
| ⚠️ ARP Spoofing | Ktoś podszywa się pod router | CRITICAL |
| 📡 DNS Tunneling | Podejrzanie dużo zapytań DNS | HIGH |
| 🔍 Port Scanning | Skanowanie portów w sieci | HIGH |
| 🚨 IoT Local Scan | Domofon/kamera próbuje łączyć z innymi urządzeniami | CRITICAL |
| 📤 IoT High Upload | Urządzenie IoT wysyła za dużo danych | HIGH |
| 🌐 IoT Unknown Server | IoT łączy się z nieznanym serwerem | HIGH |
| 🧅 Tor Connection | Połączenie z węzłem Tor | HIGH |

---

## Dzienny raport email

Każdego dnia o **20:00** (czas warszawski) NetGuard wysyła email:

```
🛡 NetGuard — Raport 28.03.2026 | Ryzyko: 🟢 NISKIE | 8 urządzeń

Urządzeń online:  8
Nowych urządzeń:  1  (iPhoneArek)
Zagrożeń:         0
```

---

## Konfiguracja

Edytuj sekcję `CONFIG` w pliku `netguard_agent.py`:

```python
CONFIG = {
    "network_range": "192.168.1.0/24",    # Twój zakres sieci
    "interface": "eth0",                   # Interfejs sieciowy
    "alert_email": "twoj@gmail.com",       # Email do powiadomień
    "trusted_macs": [
        "aa:bb:cc:dd:ee:ff",              # Zaufane urządzenia
    ],
    "device_names": {
        "aa:bb:cc:dd:ee:ff": "Mój laptop", # Nazwy urządzeń
    },
    "smtp": {
        "host": "smtp.gmail.com",
        "port": 587,
        "user": "twoj@gmail.com",
        "password": "haslo_aplikacji",     # Hasło aplikacji Gmail
    },
}
```

---

## Uruchamianie

```bash
# Podstawowe uruchomienie
sudo python3 netguard_agent.py

# Z dashboardem webowym
sudo python3 netguard_agent.py --dashboard

# Jako usługa systemd (po instalacji)
sudo systemctl start netguard
sudo systemctl status netguard
```

---

## Lokalny AI (opcjonalny)

NetGuard używa [Ollama](https://ollama.com) do lokalnej analizy AI — bez wysyłania danych do chmury.

```bash
# Zainstaluj Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pobierz model
ollama pull llama3.2

# Uruchom NetGuard z AI
sudo python3 netguard_agent.py --dashboard
```

Następnie w dashboardzie otwórz **Konsola AI** i zadaj pytanie po polsku:
> *"Czy moja sieć jest bezpieczna? Co mnie niepokoi?"*

---

## Architektura

```
netguard/
├── netguard_agent.py          # Główny agent Python
├── network-agent-dashboard.html  # Dashboard webowy
├── install.sh                 # Instalator Linux/macOS
├── install.ps1                # Instalator Windows
└── docs/
    └── screenshot.png
```

**Moduły agenta:**
- `NetworkScanner` — ARP skanowanie co 60s (Scapy)
- `PacketAnalyzer` — nasłuch pakietów w czasie rzeczywistym
- `AIAnalyst` — lokalny LLM przez Ollama
- `AlertManager` — email + dzienny raport HTML
- `WebDashboard` — Flask REST API + dashboard

---

## Prywatność

NetGuard został zaprojektowany z myślą o prywatności:

- ✅ Wszystkie dane pozostają na Twoim urządzeniu
- ✅ Lokalny LLM — prompty nie trafiają do chmury
- ✅ Brak telemetrii, brak trackerów, brak analityki
- ✅ Open source — możesz sprawdzić każdą linię kodu
- ❌ Nie nagrywa treści komunikacji
- ❌ Nie śledzi historii przeglądania

---

## Licencja

MIT License — używaj, modyfikuj, dystrybuuj swobodnie.

---

## Autor

Zbudowany z ❤️ dla ochrony prywatności sieci domowej.

⭐ Jeśli NetGuard Ci pomógł — zostaw gwiazdkę na GitHub!
