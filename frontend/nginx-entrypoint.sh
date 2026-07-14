#!/bin/sh
set -e

CERT=/etc/nginx/certs/orca.crt

echo "[nginx] Waiting for TLS certificate..."
WAIT=0
while [ ! -f "$CERT" ]; do
    sleep 1
    WAIT=$((WAIT + 1))
    if [ "$WAIT" -ge 60 ]; then
        echo "[nginx] ERROR: Timed out waiting for certificate at $CERT"
        exit 1
    fi
done
echo "[nginx] Certificate found — starting nginx..."

# Start nginx in background
nginx -g "daemon off;" &
NGINX_PID=$!

LAST=$(md5sum "$CERT" 2>/dev/null | cut -d' ' -f1)

# Watch for cert changes and reload nginx gracefully
while kill -0 "$NGINX_PID" 2>/dev/null; do
    sleep 10
    CUR=$(md5sum "$CERT" 2>/dev/null | cut -d' ' -f1)
    if [ -n "$CUR" ] && [ "$CUR" != "$LAST" ]; then
        echo "[nginx] Certificate changed — reloading nginx..."
        nginx -s reload
        LAST="$CUR"
    fi
done
