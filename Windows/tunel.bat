@echo off
SETLOCAL

echo Sprawdzam obecnosc WireGuard...

REM Sprawdz czy wireguard.exe jest w PATH lub w standardowym folderze
where wireguard.exe >nul 2>&1
set WIREGUARD_URL=https://download.wireguard.com/windows-client/wireguard-installer.exe
set INSTALLER=%TEMP%\wireguard-installer.exe
echo ERRORLEVEL = %ERRORLEVEL%
IF %ERRORLEVEL% NEQ 0 (
	ver > nul
    echo WireGuard nie znaleziony. Instaluje WireGuard...
    
	echo TEMP = %TEMP%
	echo INSTALLER = %INSTALLER%
	echo WIREGUARD_URL = %WIREGUARD_URL%
    echo Pobieranie instalatora...
    curl -L -o "%INSTALLER%" "%WIREGUARD_URL%"
	echo ERRORLEVEL = %ERRORLEVEL%

    echo Instaluje WireGuard w trybie cichym...
    "%INSTALLER%" /quiet

    del "%INSTALLER%"

    echo WireGuard zainstalowany.
) ELSE (
    echo WireGuard jest juz zainstalowany.
)

REM Dodaj WireGuard do PATH, jesli trzeba
SET PATH=%PATH%;"C:\Program Files\WireGuard"

echo Uruchamianie tunelu VPN...

wireguard.exe /installtunnelservice "%~dp0wg0.conf"

timeout /t 5 >nul
echo Sprawdzanie srodowiska Python...

REM Sprawdzenie, czy Python jest zainstalowany
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python nie znaleziony! Zainstaluj Python 3.10+ i sprobuj ponownie.
    pause
    exit /b 1
)
cd /d "%~dp0"

REM Tworzenie venv jesli nie istnieje
IF NOT EXIST venv (
    python -m venv venv
)


CALL venv\Scripts\activate.bat

echo Instalacja zaleznosci Pythona...
pip install --upgrade pip
pip install -r requirements.txt

echo Uruchamiam skan.py...
python skan.py

CALL venv\Scripts\deactivate.bat

echo Zatrzymywanie tunelu VPN...
wireguard.exe /uninstalltunnelservice wg0

echo Gotowe!
pause