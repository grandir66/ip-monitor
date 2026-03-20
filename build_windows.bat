@echo off
REM Build eseguibile per Windows x64
REM Richiede: pip install pyinstaller rich
REM Eseguire da un terminale Windows (cmd o PowerShell)

set NAME=ipmon
set SCRIPT=ping_monitor.py

echo =^> Verifica dipendenze...
python -m pip install --quiet pyinstaller rich
if errorlevel 1 (
    echo ERRORE: pip install fallito
    exit /b 1
)

echo =^> Build Windows x64 -- %NAME%.exe
python -m PyInstaller ^
    --onefile ^
    --clean ^
    --strip ^
    --name %NAME% ^
    %SCRIPT%

if exist "dist\%NAME%.exe" (
    echo.
    echo OK  Eseguibile: dist\%NAME%.exe
    echo     Uso: dist\%NAME%.exe --csv hosts.csv
) else (
    echo ERRORE: Build fallita.
    exit /b 1
)
