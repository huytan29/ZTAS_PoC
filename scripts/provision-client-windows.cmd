@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Provision one Windows client for the internal ZTAS HTTPS endpoint.
rem Run from an elevated CMD window:
rem   provision-client-windows.cmd <server-ip> <path-to-ca> [--use-dns]
rem Example:
rem   provision-client-windows.cmd 192.168.2.2 C:\Provisioning\ztas-local-ca.crt

set "ZTAS_SERVER_IP=%~1"
set "ZTAS_CA_FILE=%~2"
set "ZTAS_DNS_MODE=%~3"
set "ZTAS_HOSTNAME=ztas.ptit"
set "ZTAS_ELEVATED=%~4"
set "ZTAS_SCRIPT_PATH=%~f0"

if "%ZTAS_SERVER_IP%"=="" goto :usage
if "%ZTAS_CA_FILE%"=="" goto :usage
if /I not "%ZTAS_DNS_MODE%"=="" if /I not "%ZTAS_DNS_MODE%"=="--use-dns" goto :usage

PowerShell -NoProfile -Command "exit (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
if errorlevel 1 (
  if /I "%ZTAS_ELEVATED%"=="--elevated" (
    echo [ERROR] Windows khong cap quyen administrator cho trinh cai dat.
    exit /b 1
  )
  powershell -NoProfile -Command "$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent(); if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $q = [char]34; $arguments = '/d /c ' + $q + $env:ZTAS_SCRIPT_PATH + $q + ' ' + $q + $env:ZTAS_SERVER_IP + $q + ' ' + $q + $env:ZTAS_CA_FILE + $q + ' ' + $q + $env:ZTAS_DNS_MODE + $q + ' --elevated'; $process = Start-Process -FilePath $env:ComSpec -ArgumentList $arguments -Verb RunAs -Wait -PassThru; exit $process.ExitCode }"
  if errorlevel 1 exit /b %errorlevel%
)

powershell -NoProfile -Command "$value = $env:ZTAS_SERVER_IP; $address = $null; $valid = [System.Net.IPAddress]::TryParse($value, [ref]$address) -and $address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork; exit (-not $valid)"
if errorlevel 1 (
  echo [ERROR] '%ZTAS_SERVER_IP%' khong phai IPv4 hop le.
  exit /b 1
)

if not exist "%ZTAS_CA_FILE%" (
  echo [ERROR] Khong tim thay CA: "%ZTAS_CA_FILE%"
  exit /b 1
)

echo [INFO] CA fingerprint SHA-256:
certutil -hashfile "%ZTAS_CA_FILE%" SHA256
echo [INFO] Chi tiep tuc neu fingerprint nay do admin/server ZTAS cung cap.

certutil -addstore -f Root "%ZTAS_CA_FILE%" >nul
if errorlevel 1 (
  echo [ERROR] Khong the cai CA vao Trusted Root Certification Authorities.
  exit /b 1
)

if /I "%ZTAS_DNS_MODE%"=="--use-dns" (
  echo [INFO] Giu DNS noi bo hien co cho %ZTAS_HOSTNAME%.
) else (
  echo [INFO] Cap nhat hosts: %ZTAS_HOSTNAME% ^> %ZTAS_SERVER_IP%
  powershell -NoProfile -Command "$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; $hostName = $env:ZTAS_HOSTNAME; $ip = $env:ZTAS_SERVER_IP; $kept = @(Get-Content -LiteralPath $hosts | Where-Object { $_ -notmatch ('(^|\s)' + [regex]::Escape($hostName) + '(\s|$)') }); [System.IO.File]::WriteAllLines($hosts, @($kept) + ($ip + ' ' + $hostName), [System.Text.Encoding]::ASCII)"
  if errorlevel 1 (
    echo [ERROR] Khong the cap nhat file hosts.
    exit /b 1
  )
)

ipconfig /flushdns >nul
echo [INFO] Kiem tra HTTPS...
curl.exe --fail --silent --show-error --ssl-no-revoke "https://%ZTAS_HOSTNAME%:8443/health"
if errorlevel 1 (
  echo.
  echo [WARN] Da cai CA, nhung chua ket noi duoc server. Kiem tra IP/DNS, Firewall 8443 va server.
  exit /b 1
)

echo.
echo [DONE] May Windows da san sang: https://%ZTAS_HOSTNAME%:8443
echo [NEXT] Mo https://%ZTAS_HOSTNAME%:8443/connect-device de dang ky thiet bi neu day la may moi.
exit /b 0

:usage
echo Usage: %~nx0 ^<server-ip^> ^<path-to-ca^> [--use-dns]
echo Example: %~nx0 192.168.2.2 C:\Provisioning\ztas-local-ca.crt
echo.
echo --use-dns: khong sua file hosts, dung DNS noi bo da cau hinh.
exit /b 2
