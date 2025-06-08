#!/bin/bash

# Skrypt VPN klienta WireGuard - adres klienta: 10.0.0.3/32

# 🔐 Prywatny klucz klienta (zgodny z publicznym SCwTTn/3+JEVJHQRZgjyzzY7qzKTfG6FTfceqORNzTA=)
CLIENT_PRIVATE_KEY="sGnJ7ktdJRQ1q3lyJUi4McnBUPo4SCgHtwIEk5mP1mI="

# 🌐 Dane serwera
SERVER_IP=207.154.238.77   # przykład: 203.0.113.55
SERVER_PORT=51820
SERVER_PUBLIC_KEY="sfjKT3behAhwFqpuDhTrL4nUH0CnigD/qjKXjXavJQk="

# 🛡 Sprawdzenie uprawnień
if [[ $EUID -ne 0 ]]; then
  echo "⚠ Uruchom skrypt jako root: sudo $0"
  exit 1
fi

# 📦 Instalacja WireGuarda (jeśli nie zainstalowany)
apt update
apt install -y wireguard
apt install -y resolvconf
# 📁 Konfiguracja
mkdir -p /etc/wireguard

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.0.0.3/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg0.conf

# 🚀 Uruchomienie VPN
wg-quick up wg0

echo "✅ VPN uruchomiony. Sprawdź: ip a lub ping 10.0.0.1"

# 🐍 Tworzenie środowiska Python i uruchamianie skanera
echo "📦 Przygotowanie środowiska Python..."

SCRIPT_NAME="skan.py"

# Instalacja zależności
apt install -y python3-venv python3-pip

# Tworzenie i aktywacja środowiska venv
python3 -m venv .venv
source .venv/bin/activate

# Instalacja wymaganych paczek
pip install --upgrade pip
pip install python-gvm netifaces lxml

# Uruchomienie skryptu
echo "🚀 Uruchamiam skrypt skanowania..."
python3 "$SCRIPT_NAME"

# Dezaktywacja środowiska
deactivate
wg-quick down wg0