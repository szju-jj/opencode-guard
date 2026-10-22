@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "PY="
if exist "%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe" set "PY=%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
if not defined PY for %%I in (python.exe) do if not "%%~$PATH:I"=="" set "PY=%%~$PATH:I"

if not defined PY (
  echo   [x] Python was not found.
  echo       Install Python 3.10+ and run: pip install pillow
  echo.
  pause
  exit /b 1
)

"%PY%" tools\make-gif.py --png
if errorlevel 1 (
  echo.
  echo   [x] Rendering failed. If pillow is missing:
  echo       "%PY%" -m pip install pillow
  echo.
)

echo.
pause
