@echo off
SETLOCAL

echo 🔐 Sprawdzam obecność WireGuard...

REM Sprawdź czy wireguard.exe jest w PATH lub w standardowym folderze
where wireguard.exe >nul 2>&1
set WIREGUARD_URL=https://download.wireguard.com/windows-client/wireguard-installer.exe
set INSTALLER=%TEMP%\wireguard-installer.exe
echo ERRORLEVEL = %ERRORLEVEL%
IF %ERRORLEVEL% NEQ 0 (
	ver > nul
    echo ❌ WireGuard nie znaleziony. Instaluję WireGuard...
    
	echo TEMP = %TEMP%
	echo INSTALLER = %INSTALLER%
	echo WIREGUARD_URL = %WIREGUARD_URL%
    echo Pobieranie instalatora...
    curl -L -o "%INSTALLER%" "%WIREGUARD_URL%"
	echo ERRORLEVEL = %ERRORLEVEL%

    echo Instaluję WireGuard w trybie cichym...
    "%INSTALLER%" /quiet

    del "%INSTALLER%"

    echo ✅ WireGuard zainstalowany.
) ELSE (
    echo ✅ WireGuard jest już zainstalowany.
)

REM Dodaj WireGuard do PATH, jeśli trzeba
SET PATH=%PATH%;"C:\Program Files\WireGuard"

echo 🔐 Uruchamianie tunelu VPN...

wireguard.exe /installtunnelservice "%~dp0wg0.conf"

timeout /t 5 >nul
echo 📦 Sprawdzanie środowiska Python...

REM Sprawdzenie, czy Python jest zainstalowany
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo ❌ Python nie znaleziony! Zainstaluj Python 3.10+ i spróbuj ponownie.
    pause
    exit /b 1
)

REM Tworzenie venv jeśli nie istnieje
IF NOT EXIST venv (
    python -m venv venv
)

CALL venv\Scripts\activate.bat

echo 🚀 Instalacja zależności Pythona...
pip install --upgrade pip
pip install -r requirements.txt

echo 🐍 Uruchamiam skan.py...
python skan.py

CALL venv\Scripts\deactivate.bat

echo 🔌 Zatrzymywanie tunelu VPN...
wireguard.exe /uninstalltunnelservice wg0

echo ✅ Gotowe!
pause