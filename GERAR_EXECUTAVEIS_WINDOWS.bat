@echo off
setlocal
cd /d "%~dp0"
echo LabGuard Central - gerar os executaveis no Windows
echo Requer Python 3.10 ou superior de 64 bits e internet para as dependencias.
where py.exe >nul 2>nul
if errorlevel 1 (
  python.exe "%~dp0central\gerar_executaveis.py"
) else (
  py.exe -3 "%~dp0central\gerar_executaveis.py"
)
if errorlevel 1 (
  echo.
  echo A compilacao nao terminou. Confira a mensagem acima.
  pause
  exit /b 1
)
pause
