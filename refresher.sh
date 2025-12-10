#!/bin/bash

# Nastavení intervalu v sekundách (3600s = 1 hodina)
REFRESH_INTERVAL=3600

echo "--- Spouštím Cookie Refresher službu ---"

while true; do
    echo "-------------------------------------------"
    echo "Aktualizace stavu k: $(date)"
    
    echo "Krok 1: Spouštím Python skript pro obnovu cookies..."
    # Spustíme skript, který načte servers.json a obnoví všechny cookies
    python supersetLogin/cookie_refresher.py
    
    echo "Krok 2: Obnova dokončena. Čekám ${REFRESH_INTERVAL} sekund do dalšího spuštění."
    echo "-------------------------------------------"
    
    sleep $REFRESH_INTERVAL
done
