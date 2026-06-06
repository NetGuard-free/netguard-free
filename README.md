---
NetGuard AI — Lokalny Agent Sieci Domowej

Wersja Free (limit 5 urządzeń, 7 dni historii).
Wersja modułowa — 16 modułów w katalogu `netguard/`.

## Instalacja

Linux:
```bash
curl -sSL https://raw.githubusercontent.com/NetGuard-free/netguard-free/main/install.sh | bash
```

Windows (PowerShell jako Administrator):
```powershell
irm https://raw.githubusercontent.com/NetGuard-free/netguard-free/main/install.ps1 | iex
```

## Budowa

NetGuard używa budowy modułowej od wersji 1.5.0:
- `netguard/` — 16 plików źródłowych
- `netguard_agent.py` — cienki stub (36 linii)
- Licencja (Free/Home/Enterprise) odblokowuje funkcje w runtime

Więcej: https://netguardhome.pl

