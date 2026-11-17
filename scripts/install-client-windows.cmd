@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Double-click entry point for an end user. The bundle creator supplies the
rem CA and ztas-client-config.cmd in this same folder.
for %%I in ("%~dp0..") do set "ZTAS_BUNDLE_DIR=%%~fI\"
if not exist "%ZTAS_BUNDLE_DIR%ztas-client-config.cmd" (
  echo [ERROR] Khong tim thay ztas-client-config.cmd trong bo cai dat.
  exit /b 1
)
if not exist "%ZTAS_BUNDLE_DIR%ztas-local-ca.crt" (
  echo [ERROR] Khong tim thay ztas-local-ca.crt trong bo cai dat.
  exit /b 1
)

call "%ZTAS_BUNDLE_DIR%ztas-client-config.cmd"
call "%ZTAS_BUNDLE_DIR%provision-client-windows.cmd" "%ZTAS_SERVER_IP%" "%ZTAS_BUNDLE_DIR%ztas-local-ca.crt" "%ZTAS_DNS_MODE%"
if errorlevel 1 exit /b %errorlevel%

start "ZTAS - Ket noi thiet bi" "https://ztas.ptit:8443/connect-device"
echo [DONE] Da mo trinh duyet den trang ket noi thiet bi.
exit /b 0
