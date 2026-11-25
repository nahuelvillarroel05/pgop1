@echo off
setlocal
set "PGOP_PANEL_INSTALL_DIR=%~dp0"
if exist "%~dp0pgop-panel-env\Scripts\python.exe" goto run
py -3.14 -I -B "%~dp0install-panel.py"
if errorlevel 1 exit /b 1
:run
py -3.14 -I -S -B "%~dp0start-panel.py" %*
exit /b %errorlevel%
