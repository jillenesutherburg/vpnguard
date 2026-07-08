@echo off
chcp 65001 >nul
:: Автозапуск трея VPNGuard с правами администратора БЕЗ запроса UAC
:: (задача планировщика с Run with highest privileges - как у OpenVPN GUI).
:: То же самое делает пункт меню трея "Автозапуск без UAC".
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Запустите этот файл от имени администратора.
    pause
    exit /b 1
)

set EXE=%~dp0..\VpnGuard.Tray.exe
if not exist "%EXE%" set EXE=%~dp0VpnGuard.Tray.exe
if not exist "%EXE%" (
    echo [ОШИБКА] Не найден VpnGuard.Tray.exe
    pause
    exit /b 1
)

schtasks /Create /F /TN "VPNGuard Tray" /TR "\"%EXE%\"" /SC ONLOGON /RL HIGHEST /IT
if errorlevel 1 (
    echo [ОШИБКА] Не удалось создать задачу.
    pause
    exit /b 1
)

echo [OK] Трей будет стартовать при входе в систему с наивысшими правами без UAC.
schtasks /Run /TN "VPNGuard Tray"
pause
