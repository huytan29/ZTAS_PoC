@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Create an unpacked, no-argument client installer folder from a Windows ZTAS server.
rem Usage: create-client-bundle-windows.cmd <server-ip> [--use-dns]

for %%I in ("%~dp0..") do set "ZTAS_PROJECT_ROOT=%%~fI"
set "ZTAS_SERVER_IP=%~1"
set "ZTAS_DNS_MODE=%~2"
set "ZTAS_BUNDLE_DIR=%ZTAS_PROJECT_ROOT%\Client_PoC"
set "ZTAS_LAUNCHER_DIR=%ZTAS_BUNDLE_DIR%\Client"
set "ZTAS_CA_FILE=%ZTAS_PROJECT_ROOT%\runtime\ztas-local-ca.crt"

if "%ZTAS_SERVER_IP%"=="" goto :usage
if /I not "%ZTAS_DNS_MODE%"=="" if /I not "%ZTAS_DNS_MODE%"=="--use-dns" goto :usage

powershell -NoProfile -Command "$value = $env:ZTAS_SERVER_IP; $address = $null; $valid = [System.Net.IPAddress]::TryParse($value, [ref]$address) -and $address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork; exit (-not $valid)"
if errorlevel 1 (
  echo [ERROR] '%ZTAS_SERVER_IP%' khong phai IPv4 hop le.
  exit /b 1
)

if not exist "%ZTAS_CA_FILE%" (
  echo [ERROR] Chua co "%ZTAS_CA_FILE%".
  echo [NEXT] Chay mingw32-make deploy-https ZTAS_SERVER_IP=%ZTAS_SERVER_IP% truoc.
  exit /b 1
)

if exist "%ZTAS_BUNDLE_DIR%" rmdir /s /q "%ZTAS_BUNDLE_DIR%"
mkdir "%ZTAS_BUNDLE_DIR%"
mkdir "%ZTAS_LAUNCHER_DIR%"
copy /Y "%ZTAS_CA_FILE%" "%ZTAS_BUNDLE_DIR%\ztas-local-ca.crt" >nul
copy /Y "%ZTAS_PROJECT_ROOT%\scripts\provision-client-windows.cmd" "%ZTAS_BUNDLE_DIR%" >nul
copy /Y "%ZTAS_PROJECT_ROOT%\scripts\provision-client-ubuntu.sh" "%ZTAS_BUNDLE_DIR%" >nul
copy /Y "%ZTAS_PROJECT_ROOT%\scripts\provision-client-macos.sh" "%ZTAS_BUNDLE_DIR%" >nul
copy /Y "%ZTAS_PROJECT_ROOT%\scripts\install-client-windows.cmd" "%ZTAS_LAUNCHER_DIR%\CAI-ZTAS-Windows.cmd" >nul
copy /Y "%ZTAS_PROJECT_ROOT%\scripts\install-client-ubuntu.sh" "%ZTAS_LAUNCHER_DIR%\CAI-ZTAS-Ubuntu.sh" >nul
copy /Y "%ZTAS_PROJECT_ROOT%\scripts\install-client-macos.command" "%ZTAS_LAUNCHER_DIR%\CAI-ZTAS-macOS.command" >nul

> "%ZTAS_BUNDLE_DIR%\ztas-client-config.cmd" echo set "ZTAS_SERVER_IP=%ZTAS_SERVER_IP%"
>> "%ZTAS_BUNDLE_DIR%\ztas-client-config.cmd" echo set "ZTAS_DNS_MODE=%ZTAS_DNS_MODE%"
> "%ZTAS_BUNDLE_DIR%\ztas-client-config.sh" echo ZTAS_SERVER_IP='%ZTAS_SERVER_IP%'
>> "%ZTAS_BUNDLE_DIR%\ztas-client-config.sh" echo ZTAS_DNS_MODE='%ZTAS_DNS_MODE%'

echo.
echo [DONE] Thu muc cai dat: %ZTAS_BUNDLE_DIR%
echo [ADMIN] Chia se/chep NGUYEN thu muc nay; end user chi mo file trong Client\.
echo [USER] Windows: double-click CAI-ZTAS-Windows.cmd va chap nhan UAC.
echo [USER] Ubuntu: double-click/run CAI-ZTAS-Ubuntu.sh, nhap mat khau he thong.
echo [USER] macOS: double-click CAI-ZTAS-macOS.command, nhap mat khau he thong.
exit /b 0

:usage
echo Usage: %~nx0 ^<server-ip^> [--use-dns]
echo Example: %~nx0 192.168.2.2
exit /b 2
