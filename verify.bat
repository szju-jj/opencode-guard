@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "NODE_EXE="

rem 1) normal install on PATH
for %%I in (node.exe) do if not "%%~$PATH:I"=="" set "NODE_EXE=%%~$PATH:I"

rem 2) the runtime bundled with WorkBuddy
if not defined NODE_EXE if exist "%USERPROFILE%\.workbuddy\binaries\node\versions\current\node.exe" set "NODE_EXE=%USERPROFILE%\.workbuddy\binaries\node\versions\current\node.exe"

rem 3) any bundled version directory
if not defined NODE_EXE for /d %%D in ("%USERPROFILE%\.workbuddy\binaries\node\versions\*") do if exist "%%~fD\node.exe" set "NODE_EXE=%%~fD\node.exe"

rem 4) the usual Windows installers
if not defined NODE_EXE if exist "%ProgramFiles%\nodejs\node.exe" set "NODE_EXE=%ProgramFiles%\nodejs\node.exe"
if not defined NODE_EXE if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" set "NODE_EXE=%LOCALAPPDATA%\Programs\nodejs\node.exe"

rem 5) version managers
if not defined NODE_EXE if exist "%USERPROFILE%\.volta\bin\node.exe" set "NODE_EXE=%USERPROFILE%\.volta\bin\node.exe"
if not defined NODE_EXE if exist "%APPDATA%\nvm\node.exe" set "NODE_EXE=%APPDATA%\nvm\node.exe"

if not defined NODE_EXE (
  echo.
  echo   [x] Node.js was not found on this machine.
  echo.
  echo   Install Node 22.18 or newer from https://nodejs.org
  echo   then double-click this file again.
  echo.
  pause
  exit /b 1
)

if not exist "demo\verify-once.ts" (
  echo.
  echo   [x] demo\verify-once.ts is missing.
  echo   Make sure you run this file from inside the opencode-guard folder.
  echo.
  pause
  exit /b 1
)

"%NODE_EXE%" "demo\verify-once.ts"

echo.
echo   Press any key to close this window.
pause >nul
