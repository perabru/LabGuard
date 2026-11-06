@echo off
cd /d "%~dp0"
py -3 main.py
if errorlevel 1 (
  echo.
  echo Nao foi possivel iniciar. Instale Python 3.10 ou superior com Tcl/Tk.
  pause
)
