#!/bin/bash
# MaxMind GeoLite2 database updater
# Runs geoipupdate and signals the receiver to reload databases

LOG_PREFIX="[geoip-update]"

echo "$LOG_PREFIX Starting GeoLite2 database update..."

# Run geoipupdate
if geoipupdate -d /app/maxmind -f /etc/GeoIP.conf -v 2>&1; then
    echo "$LOG_PREFIX GeoLite2 databases updated successfully"

    # Signal receiver to reload databases (SIGUSR1)
    RECEIVER_PID=$(pgrep -f "python.*main.py" | head -1)
    if [ -n "$RECEIVER_PID" ]; then
        kill -USR1 "$RECEIVER_PID"
        echo "$LOG_PREFIX Sent reload signal to receiver (PID $RECEIVER_PID)"
    else
        echo "$LOG_PREFIX WARNING: Receiver process not found, databases will load on next restart"
    fi
else
    echo "$LOG_PREFIX ERROR: geoipupdate failed"
fi
