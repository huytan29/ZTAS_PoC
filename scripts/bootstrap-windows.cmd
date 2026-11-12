@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Bootstrap lan dau cho Windows. Chay tu CMD, khong can PowerShell.
rem Dung: bootstrap-windows.cmd [thu_muc_dich]
set "REPOSITORY_URL=https://github.com/huytan29/ZTAS_PoC.git"
set "REPOSITORY_BRANCH=main"
set "DEFAULT_TARGET=%USERPROFILE%\source\ZTAS_PoC"
set "TARGET_DIR=%~1"
if "%TARGET_DIR%"=="" set "TARGET_DIR=%DEFAULT_TARGET%"

where git >nul 2>&1
if errorlevel 1 (
  echo [LOI] Chua tim thay Git trong PATH.
  echo       Cai Git for Windows, mo CMD moi, roi chay lai script nay.
  exit /b 1
)

if exist "%TARGET_DIR%" (
  echo [DUNG] Thu muc dich da ton tai: "%TARGET_DIR%"
  echo        Script khong ghi de source da co. Hay chon thu muc trong hoac cap nhat repo thu cong.
  exit /b 2
)

for %%I in ("%TARGET_DIR%") do set "PARENT_DIR=%%~dpI"
if not exist "%PARENT_DIR%" mkdir "%PARENT_DIR%"
if errorlevel 1 (
  echo [LOI] Khong tao duoc thu muc cha: "%PARENT_DIR%"
  exit /b 1
)

echo [1/2] Dang clone ZTAS PoC tu GitHub...
git clone --origin origin --branch "%REPOSITORY_BRANCH%" --single-branch "%REPOSITORY_URL%" "%TARGET_DIR%"
if errorlevel 1 (
  echo [LOI] Git clone that bai. Kiem tra ket noi mang va quyen truy cap repository.
  exit /b 1
)

echo [2/2] Da tai source thanh cong.
echo.
echo Thu muc du an: "%TARGET_DIR%"
echo.
echo Buoc tiep theo trong CMD:
echo   cd /d "%TARGET_DIR%"
echo   set "VCPKG_ROOT=%%USERPROFILE%%\vcpkg"
echo   mingw32-make build
echo   mingw32-make run
echo.
echo Yeu cau: Git, CMake, MinGW-w64, vcpkg va Docker Desktop da duoc cai dat.
endlocal
