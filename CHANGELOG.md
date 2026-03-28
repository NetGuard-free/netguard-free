# Changelog — NetGuard AI

Wszystkie istotne zmiany w projekcie są dokumentowane w tym pliku.
Format oparty na [Keep a Changelog](https://keepachangelog.com/pl/1.0.0/).

---

## [1.0.0] — 2026-03-28

### Pierwsze wydanie publiczne

#### Dodano
- Skanowanie sieci przez ARP co 60 sekund (Scapy)
- Wykrywanie nowych i nieznanych urządzeń w sieci
- Analiza pakietów w czasie rzeczywistym:
  - Wykrywanie ARP Spoofing
  - Wykrywanie DNS Tunneling
  - Wykrywanie skanowania portów
  - Wykrywanie połączeń z węzłami Tor
  - Wykrywanie złośliwych domen DNS
- Specjalny moduł monitorowania urządzeń IoT (Tuya, smart home):
  - Detekcja skanowania sieci lokalnej przez IoT
  - Alert przy nadmiernym uploadu
  - Alert przy połączeniu z nieznanym serwerem
- Lokalny LLM przez Ollama (llama3.2) — analiza sieci bez chmury
- Web dashboard (Flask, port 8767):
  - Lista urządzeń z filtrami (online, nowe, podejrzane, zablokowane)
  - Dziennik alertów z opisami zagrożeń
  - Analiza zagrożeń w czasie rzeczywistym
  - Konsola AI po polsku
  - Modal szczegółów urządzenia (edycja nazwy, oznacz jako zaufane, blokuj)
  - Modal szczegółów alertu z opisem zagrożenia i poziomem ryzyka
  - Powiadomienia push przy pojawieniu/opuszczeniu urządzenia
- Dzienny raport email o 20:00 (czas warszawski) — HTML z podsumowaniem dnia
- Natychmiastowe alerty email dla zdarzeń CRITICAL i HIGH
- Synchronizacja urządzeń z lokalnej tablicy ARP (/proc/net/arp)
- Wizard pierwszego uruchomienia — auto-wykrycie sieci i konfiguracja
- Plik config.json — konfiguracja oddzielona od kodu
- Zmiany nazw i zaufanych urządzeń zapisywane trwale w config.json
- Endpoint /api/test-report do testowania emaili
- Automatyczne otwieranie przeglądarki po uruchomieniu
- Instalator Linux/macOS/RPi (install.sh):
  - Auto-wykrycie systemu i interfejsu
  - Konfiguracja systemd (autostart)
  - Skrót w menu aplikacji i na pulpicie
- Instalator Windows (install.ps1):
  - Instalacja Python przez winget
  - Task Scheduler (autostart przy logowaniu)
  - Skrót na pulpicie
- Wsparcie Docker (Dockerfile)

#### Wymagania
- Python 3.9+
- Linux / macOS / Windows (WSL2) / Raspberry Pi OS
- Uprawnienia root/sudo (do skanowania ARP i iptables)
- Opcjonalnie: Ollama + llama3.2 (lokalny LLM)
- Opcjonalnie: Npcap (Windows, do skanowania ARP)

---

## Planowane w v1.1.0

- Aplikacja mobilna (iOS/Android) — push notyfikacje
- Integracja z routerami (pobieranie pełnej listy urządzeń)
- Automatyczna aktualizacja bazy złośliwych domen
- Wykrywanie słabych haseł WiFi
- Mapa topologii sieci w dashboardzie
- Eksport raportów do PDF
- Obsługa wielu sieci jednocześnie
