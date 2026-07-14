@echo off
echo [ORCA Agent Installer]
echo.
set /p SERVER_URL="Enter ORCA server URL (e.g. https://10.11.110.60:8000): "
set /p TOKEN="Enter your JWT token: "

echo { "server_url": "%SERVER_URL%", "token": "%TOKEN%", "bin_dir": "./bin", "poll_interval": 5 } > config.json

pip install requests 2>nul

sc create "ORCA_Agent" binPath= "python \"%~dp0orca_agent.py\"" start= auto DisplayName= "ORCA Forensic Agent"
sc description "ORCA_Agent" "ORCA dead disk and local analysis agent"
sc start "ORCA_Agent"

echo.
echo [ORCA Agent installed and started]
echo Agent will connect to %SERVER_URL%
pause
