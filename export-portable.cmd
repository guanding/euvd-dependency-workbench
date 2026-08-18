@echo off
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\export-portable.ps1"
if errorlevel 1 pause
