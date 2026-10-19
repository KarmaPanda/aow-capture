@echo off
rem Builds dist\AoWCapture.exe (+ zip and checksums). Needs Python 3.10+ on PATH.
setlocal
cd /d "%~dp0"
python -m pip install --upgrade -r requirements.txt pyinstaller || goto :fail
python build.py || goto :fail
echo.
echo Done. For a release, push a tag instead (see README).
pause
exit /b 0
:fail
echo Build failed.
pause
exit /b 1
