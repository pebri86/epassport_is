@echo off
rem Build the eMRTD Reader as a single-file executable with PyInstaller.
rem Usage:  packaging\build.bat
rem Output: dist\eMRTDReader.exe
setlocal

cd /d "%~dp0\.."

rem Use the project venv python if present, else the system python.
set PY=.venv\Scripts\python.exe
if not exist "%PY%" set PY=python

echo [build] using python: 
%PY% --version

echo [build] installing runtime deps + pyinstaller ...
%PY% -m pip install --quiet -r requirements.txt -r packaging\requirements-build.txt

echo [build] running PyInstaller (one-file, windowed) ...
%PY% -m PyInstaller --noconfirm --clean packaging\eMRTDReader.spec

echo [build] done.
dir dist\eMRTDReader.exe

endlocal
