@echo off
setlocal EnableExtensions

rem Bootstrap the project-local vcpkg used by every Windows build.
for %%I in ("%~dp0..") do set "ZTAS_PROJECT_ROOT=%%~fI"
set "VCPKG_DIR=%ZTAS_PROJECT_ROOT%\.vcpkg"

if exist "%VCPKG_DIR%\vcpkg.exe" (
  "%VCPKG_DIR%\vcpkg.exe" version >nul 2>&1 && goto :ready
)
where git >nul 2>&1 || (
  echo [ERROR] Can Git de tai vcpkg tu GitHub.
  exit /b 1
)
if not exist "%VCPKG_DIR%\bootstrap-vcpkg.bat" (
  if exist "%VCPKG_DIR%" (
    echo [INFO] Xoa .vcpkg dang do va tai lai...
    rmdir /s /q "%VCPKG_DIR%"
  )
  echo [INFO] Dang tai vcpkg lan dau...
  git clone https://github.com/microsoft/vcpkg "%VCPKG_DIR%" || exit /b 1
)
echo [INFO] Dang bootstrap vcpkg...
call "%VCPKG_DIR%\bootstrap-vcpkg.bat" -disableMetrics || exit /b 1

:ready
echo [INFO] vcpkg san sang: %VCPKG_DIR%
