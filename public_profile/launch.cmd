@echo off
"%~dp0..\.venv\Scripts\python.exe" "%~dp0..\runtime\candidate\pg_i7.py" --profile public %*
exit /b %errorlevel%
