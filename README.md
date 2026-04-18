# NetGuard AI — Agent Sieci Domowej (Wersja Free)

> Lokalny agent który monitoruje Twoją sieć domową, wykrywa zagrożenia i codziennie wysyła raport emailowy. Zero chmury. 100% prywatności.

![NetGuard Dashboard](https://raw.githubusercontent.com/NetGuard-free/netguard-free/main/docs/Screenshot.png)

---

## Co robi NetGuard Free?

- **Wykrywa urządzenia** — skanuje sieć i powiadamia o nowych, nieznanych urządzeniach (limit 5 urządzeń)
- **Wykrywa zagrożenia** — ARP Spoofing, DNS Tunneling, Port Scanning, anomalie IoT, połączenia Tor
- **Monitoruje ruch** — wykres ruchu sieciowego w czasie, top urządzenia i porty
- **Dzienny raport email** — o 20:00 wysyła podsumowanie dnia
- **100% lokalnie** — żadne dane nie opuszczają Twojej sieci

### Ograniczenia wersji Free

| Funkcja | Free | Home |
|---|---|---|
| Wykrywanie urządzeń | do 5 urządzeń | do 25 urządzeń |
| Historia alertów | 7 dni | 30 dni |
| AI Chat (analiza sieci) | niedostępne | dostępne |
| Lokalny LLM (Ollama) | niedostępne | dostępne |
| Zdalny dostęp do panelu | niedostępne | dostępne |

Pełna wersja Home dostępna na [netguardhome.pl](https://netguardhome.pl).

---

## Szybka instalacja

### Linux / Raspberry Pi / macOS

```bash
curl -sSL https://netguardhome.pl/install.sh | bash
```

### Windows (PowerShell jako Administrator)

> **Jak otworzyć PowerShell jako Administrator:**
> Naciśnij klawisz **Windows**, wpisz `PowerShell`, kliknij prawym przyciskiem myszy na **Windows PowerShell** i wybierz **"Uruchom jako administrator"**.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
irm https://netguardhome.pl/install.ps1 | iex
```

Instalator automatycznie pobierze Python, Npcap i wszystkie biblioteki. Na końcu ustawi hasło do panelu admina.

Po instalacji otwórz: **http://localhost:8767**

---

## Wymagania

| System | Wymagania |
|---|---|
| Linux / RPi | Python 3.9+, uprawnienia root/sudo |
| macOS | Python 3.9+ |
| Windows 10/11 | Python 3.9+, [Npcap](https://npcap.com/#download) |

---

## Co wykrywa?

| Zagrożenie | Opis | Poziom |
|---|---|---|
| Nowe urządzenie | Nieznany MAC w sieci | HIGH |
| ARP Spoofing | Ktoś podszywa się pod router lub inne urządzenie | CRITICAL |
| DNS Tunneling | Podejrzanie duża liczba zapytań DNS z jednego hosta | HIGH |
| Port Scanning | Skanowanie portów w sieci lokalnej | HIGH |
| IoT Local Scan | Urządzenie IoT próbuje łączyć się z innymi urządzeniami | CRITICAL |
| IoT High Upload | Urządzenie IoT wysyła za dużo danych na zewnątrz | HIGH |
| IoT Unknown Server | IoT łączy się z nieznanym serwerem zewnętrznym | HIGH |
| Tor Connection | Połączenie z węzłem sieci Tor | HIGH |
| Malicious DNS | Zapytanie do złośliwej domeny | CRITICAL |

---

## Dzienny raport email

Każdego dnia o **20:00** (czas warszawski) NetGuard wysyła raport:

```
NetGuard — Raport 18.04.2026 | Ryzyko: NISKIE | 4 urządzenia

Urzadzen online:  4
Nowych urzadzen:  1  (iPhone-Arek)
Zagrozen:         0
```

Konfiguracja SMTP w `config.json` (sekcja `smtp`). Działa z Gmail (hasło aplikacji), jak i z innymi serwerami pocztowymi.

---

## Konfiguracja

Przy pierwszym uruchomieniu kreator automatycznie wykrywa sieć i pyta o podstawowe ustawienia. Konfiguracja zapisywana jest w pliku `config.json`.

```json
{
  "network_range": "192.168.1.0/24",
  "interface": "auto",
  "alert_email": "twoj@gmail.com",
  "dashboard_port": 8767,
  "smtp": {
    "host": "smtp.gmail.com",
    "port": 587,
    "user": "twoj@gmail.com",
    "password": "haslo_aplikacji_gmail"
  }
}
```

Zaufane urządzenia i ich nazwy zapisywane są w osobnym pliku `netguard_devices.json`.

> `config.json` zawiera dane osobowe — nie wgrywaj go na GitHub.

---

## Uruchamianie

```bash
# Linux / macOS
sudo python3 netguard_agent.py --dashboard

# Lub przez systemd (po instalacji instalatorem)
sudo systemctl start netguard
sudo systemctl status netguard
```

Na Windows użyj skrótu **NetGuard AI** na pulpicie lub pliku `start.bat` w katalogu `%USERPROFILE%\netguard\`.

Aby zatrzymać: naciśnij **Ctrl+C** w oknie konsoli.

---

## Rozwiązywanie problemów — Windows

### Przeglądarka pokazuje "Serwer odrzucił połączenie"

Oznacza to że agent nie działa. Najczęstsza przyczyna — brak pliku `config.json`.

**Sprawdź:** Eksplorator plików → `C:\Users\TwojaNazwa\netguard\` — czy jest `config.json`?

**Brak `config.json`** — uruchom instalator ponownie jako Administrator:
```powershell
irm https://netguardhome.pl/install.ps1 | iex
```

**`config.json` istnieje ale agent nie startuje:**
1. Przejdź do `C:\Users\TwojaNazwa\netguard\`
2. Uruchom `start.bat`
3. Sprawdź błędy w oknie konsoli
4. Otwórz `http://localhost:8767`

**Błąd o Npcap** — zainstaluj [Npcap](https://npcap.com/#download) ręcznie i zaznacz **"WinPcap API compatible mode"**.

---

## Architektura

```
netguard-free/
├── netguard_agent.py             # Agent Python — skanowanie, wykrywanie, API
├── network-agent-dashboard.html  # Dashboard webowy (lokalny)
├── install.sh                    # Instalator Linux/macOS
├── install.ps1                   # Instalator Windows
├── netguard.ico                  # Ikona aplikacji Windows
└── docs/
    └── Screenshot.png
```

**Moduły agenta:**
- `NetworkScanner` — skanowanie ARP co 60s + ping sweep (Windows)
- `PacketAnalyzer` — nasłuch pakietów Scapy + pomiar I/O psutil
- `RouterSync` — odczyt lokalnej tablicy ARP (`arp -a` / `/proc/net/arp`)
- `AlertManager` — email + dzienny raport HTML
- `WebDashboard` — Flask REST API + dashboard

---

## Prywatność

- Wszystkie dane pozostają na Twoim urządzeniu
- Brak telemetrii, brak trackerów, brak analityki
- Open source — możesz sprawdzić każdą linię kodu
- Agent nie nagrywa treści komunikacji
- Agent nie śledzi historii przeglądania

---

## Licencja

Udostępniany na licencji Business Source License 1.1 — szczegóły w pliku [LICENSE](LICENSE).

Dozwolony użytek: domowy i niekomercyjny. Wersja komercyjna (Home/Enterprise): [netguardhome.pl](https://netguardhome.pl).

---

Zbudowany dla ochrony prywatności sieci domowej.

Jeśli NetGuard Ci pomógł — zostaw gwiazdkę na GitHub!
