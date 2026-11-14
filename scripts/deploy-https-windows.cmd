@echo off
setlocal EnableExtensions

rem One-command HTTPS deployment for the Windows host running ZTAS.
rem Run this file from an elevated CMD window:
rem   scripts\deploy-https-windows.cmd [server-ip]

for %%I in ("%~dp0..") do set "ZTAS_PROJECT_ROOT=%%~fI"
set "ZTAS_SERVER_IP=%~1"
set "CADDY_DIRECTORY=C:\Tools\Caddy"
set "CADDY_BIN=%CADDY_DIRECTORY%\caddy.exe"
set "CADDY_DOWNLOAD=https://caddyserver.com/api/download?os=windows&arch=amd64"

powershell -NoProfile -Command "exit (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
if errorlevel 1 (
  echo [ERROR] Hay mo CMD bang Run as administrator roi chay lai script nay.
  exit /b 1
)

if "%ZTAS_SERVER_IP%"=="" (
  echo [ERROR] Can truyen IPv4 cua Windows Server, vi du:
  echo         scripts\deploy-https-windows.cmd 192.168.2.2
  exit /b 1
)

powershell -NoProfile -Command "$value = '%ZTAS_SERVER_IP%'; exit (-not [System.Net.IPAddress]::TryParse($value, [ref]([System.Net.IPAddress]$null)))"
if errorlevel 1 (
  echo [ERROR] '%ZTAS_SERVER_IP%' khong phai IPv4/IPv6 hop le.
  exit /b 1
)

echo [INFO] Windows server IPv4: %ZTAS_SERVER_IP%

if not exist "%CADDY_BIN%" (
  echo [INFO] Dang tai Caddy tu nguon chinh thuc...
  if not exist "%CADDY_DIRECTORY%" mkdir "%CADDY_DIRECTORY%"
  curl.exe --fail --location --output "%CADDY_BIN%.download" "%CADDY_DOWNLOAD%"
  if errorlevel 1 (
    echo [ERROR] Khong the tai Caddy. Kiem tra ket noi Internet/proxy roi chay lai.
    exit /b 1
  )
  move /Y "%CADDY_BIN%.download" "%CADDY_BIN%" >nul
)

"%CADDY_BIN%" version || exit /b 1

rem Keep the hostname stable even when the server receives another LAN address.
powershell -NoProfile -Command "$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; $ip = '%ZTAS_SERVER_IP%'; $kept = @(Get-Content -LiteralPath $hosts | Where-Object { $_ -notmatch '(^|\s)ztas\.ptit(\s|$)' }); [System.IO.File]::WriteAllLines($hosts, @($kept) + ($ip + ' ztas.ptit'), [System.Text.Encoding]::ASCII)"
if errorlevel 1 (
  echo [ERROR] Khong the cap nhat file hosts.
  exit /b 1
)

powershell -NoProfile -Command "if (-not (Get-NetFirewallRule -DisplayName 'ZTAS HTTPS 8443' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'ZTAS HTTPS 8443' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8443 -Profile Private | Out-Null }"
if errorlevel 1 (
  echo [ERROR] Khong the mo Firewall cho HTTPS.
  exit /b 1
)

cd /d "%ZTAS_PROJECT_ROOT%"
call mingw32-make stop
call mingw32-make run
if errorlevel 1 exit /b 1

set "ZTAS_CA=runtime\caddy-data\pki\authorities\local\root.crt"
for /l %%A in (1,1,8) do (
  if exist "%ZTAS_CA%" goto :export_ca
  timeout /t 1 /nobreak >nul
)
echo [WARN] Caddy da khoi dong nhung chua tim thay CA. Xem runtime\caddy.stderr.log
exit /b 1

:export_ca
copy /Y "%ZTAS_CA%" "runtime\ztas-local-ca.crt" >nul
echo.
echo [DONE] Dashboard: https://ztas.ptit:8443/dashboard
echo [DONE] CA cho Ubuntu: %ZTAS_PROJECT_ROOT%\runtime\ztas-local-ca.crt
echo [NEXT] Chep CA sang Ubuntu, them dong '%ZTAS_SERVER_IP% ztas.ptit' vao /etc/hosts, sau do cai CA bang update-ca-certificates.
