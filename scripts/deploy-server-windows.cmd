@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem One-command Windows Server deployment. Run from an elevated CMD:
rem   mingw32-make deploy

for %%I in ("%~dp0..") do set "ZTAS_PROJECT_ROOT=%%~fI"
if "%VCPKG_ROOT%"=="" set "VCPKG_ROOT=%USERPROFILE%\vcpkg"
if exist "C:\msys64\mingw64\bin\mingw32-make.exe" set "PATH=C:\msys64\mingw64\bin;%PATH%"

powershell -NoProfile -Command "exit (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
if errorlevel 1 (
  echo [ERROR] Hay mo CMD bang Run as administrator roi chay: mingw32-make deploy
  exit /b 1
)

where mingw32-make >nul 2>&1 || (
  echo [ERROR] Khong tim thay MinGW-w64. Can C:\msys64\mingw64\bin trong PATH.
  exit /b 1
)
where g++ >nul 2>&1 || (
  echo [ERROR] Khong tim thay g++. Cai MinGW-w64 x64 truoc.
  exit /b 1
)
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
  echo [ERROR] Khong tim thay vcpkg tai "%VCPKG_ROOT%".
  echo         Cai vcpkg tai %USERPROFILE%\vcpkg hoac dat bien VCPKG_ROOT.
  exit /b 1
)

for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-server-ip-windows.ps1"`) do set "ZTAS_SERVER_IP=%%I"
if "%ZTAS_SERVER_IP%"=="" (
  echo [ERROR] Khong tu nhan duoc IPv4 LAN. Kiem tra ket noi mang.
  exit /b 1
)

echo [INFO] VCPKG_ROOT=%VCPKG_ROOT%
echo [INFO] IPv4 LAN tu dong: %ZTAS_SERVER_IP%
cd /d "%ZTAS_PROJECT_ROOT%"
call mingw32-make deploy-https ZTAS_SERVER_IP=%ZTAS_SERVER_IP%
exit /b %errorlevel%
