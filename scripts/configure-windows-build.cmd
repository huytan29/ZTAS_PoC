@echo off
setlocal EnableExtensions

rem Allow a plain CMD window to find the documented CMake and MSYS2 MinGW64.
set "ZTAS_VCPKG_DIR=%~1"
if "%ZTAS_VCPKG_DIR%"=="" set "ZTAS_VCPKG_DIR=%~dp0..\.vcpkg"

if exist "C:\Program Files\CMake\bin\cmake.exe" set "PATH=C:\Program Files\CMake\bin;%PATH%"
if exist "C:\msys64\mingw64\bin\g++.exe" set "PATH=C:\msys64\mingw64\bin;%PATH%"

where cmake >nul 2>&1 || (
  echo [ERROR] Khong tim thay CMake. Cai CMake va chon Add CMake to PATH.
  exit /b 1
)
where g++ >nul 2>&1 || (
  echo [ERROR] Khong tim thay MinGW-w64 g++. Cai MSYS2 MinGW64 hoac them no vao PATH.
  exit /b 1
)
where mingw32-make >nul 2>&1 || (
  echo [ERROR] Khong tim thay mingw32-make. Cai MSYS2 MinGW64 hoac them no vao PATH.
  exit /b 1
)

rem CMake above is available through PATH.  Do not set
rem VCPKG_FORCE_SYSTEM_BINARIES here: vcpkg may legitimately need to fetch its
rem own PowerShell helper on a new Windows machine.
set "VCPKG_FORCE_SYSTEM_BINARIES="
set "VCPKG_ROOT=%ZTAS_VCPKG_DIR%"
set "VCPKG_DEFAULT_TRIPLET=x64-mingw-static"
set "VCPKG_DEFAULT_HOST_TRIPLET=x64-mingw-static"

cmake --preset windows -DCMAKE_TOOLCHAIN_FILE="%ZTAS_VCPKG_DIR%\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-mingw-static -DCMAKE_MAKE_PROGRAM=mingw32-make -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
exit /b %ERRORLEVEL%
