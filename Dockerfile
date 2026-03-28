FROM python:3.11-slim-bookworm

LABEL maintainer="NetGuard AI"
LABEL description="NetGuard AI — Lokalny Agent Sieci Domowej"
LABEL version="1.0.0"

# Zależności systemowe
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    net-tools \
    avahi-utils \
    samba-common-bin \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Katalog roboczy
WORKDIR /app

# Zależności Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pliki agenta
COPY netguard_agent.py .
COPY network-agent-dashboard.html .

# Port dashboardu
EXPOSE 8767

# Wolumen na dane
VOLUME ["/var/lib/netguard", "/var/log"]

# Zmienne środowiskowe (można nadpisać przez docker run -e)
ENV NETGUARD_EMAIL=""
ENV NETGUARD_NETWORK="192.168.1.0/24"
ENV NETGUARD_INTERFACE="eth0"
ENV NETGUARD_PORT="8767"

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8767/api/stats || exit 1

CMD ["python3", "netguard_agent.py", "--dashboard"]
