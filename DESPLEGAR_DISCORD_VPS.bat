@echo off
title DESPLEGAR DISCORD AI SENTINEL AL VPS (2.25.121.124)
color 0b
echo ===============================================================================
echo     DESPLEGAR DISCORD AI SENTINEL (v2.2.0) AL VPS (2.25.121.124)
echo     Ejecucion 24/7 en segundo plano con demonio systemd y autoreinicio
echo ===============================================================================
echo.
echo [1/3] Subiendo archivos del bot a /root/discord_ai_sentinel/...
echo (Introduce la contrasenia de root del VPS si te la solicita)
ssh root@2.25.121.124 "mkdir -p /root/discord_ai_sentinel"
scp -r "C:\Users\luis\discord_mod\*" root@2.25.121.124:/root/discord_ai_sentinel/

echo.
echo [2/3] Instalando dependencias y configurando servicio systemd en el VPS...
ssh root@2.25.121.124 "python3 -m pip install --break-system-packages -r /root/discord_ai_sentinel/requirements.txt 2>/dev/null || python3 -m pip install -r /root/discord_ai_sentinel/requirements.txt; echo '[Unit]\nDescription=Discord AI Sentinel Security Bot\nAfter=network.target\n\n[Service]\nType=simple\nUser=root\nWorkingDirectory=/root/discord_ai_sentinel\nEnvironmentFile=/root/discord_ai_sentinel/.env\nExecStart=/usr/bin/python3 /root/discord_ai_sentinel/sentinel_discord_bot.py\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/discord-sentinel.service && systemctl daemon-reload && systemctl enable discord-sentinel.service && systemctl restart discord-sentinel.service"

echo.
echo [3/3] Verificando estado en vivo del servicio...
ssh root@2.25.121.124 "systemctl status discord-sentinel.service --no-pager | head -n 12"

echo.
echo ===============================================================================
echo  DESPLIEGUE FINALIZADO CON EXITO!
echo  El bot esta corriendo 24/7 en segundo plano en tu VPS de Houston.
echo ===============================================================================
pause
