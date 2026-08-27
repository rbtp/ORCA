#!/bin/sh
set -e

CERT_DIR=/app/certs
CERT=$CERT_DIR/orca.crt
KEY=$CERT_DIR/orca.key

mkdir -p "$CERT_DIR"

# ORCA_SERVER_URL is the address remote collection targets actually connect
# back to (baked into every deployed package) -- it's frequently the host's
# LAN IP, not the container's own Docker-bridge IP that `hostname -I` would
# give us. A cert whose SAN doesn't cover it fails real TLS validation on
# every target (surfaces on Windows as a generic "Unable to connect to the
# remote server", not an obvious cert error) once push-delivery's real
# cert-trust import (cert_trusted=True, no TrustAll bypass) is in play.
EXTERNAL_HOST=""
if [ -n "$ORCA_SERVER_URL" ]; then
    EXTERNAL_HOST=$(echo "$ORCA_SERVER_URL" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*##')
fi

REGEN=0
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    REGEN=1
elif [ -n "$EXTERNAL_HOST" ] && ! openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -q "$EXTERNAL_HOST"; then
    echo "[ORCA] Existing certificate does not cover ORCA_SERVER_URL host (${EXTERNAL_HOST}) — regenerating..."
    REGEN=1
fi

if [ "$REGEN" = "1" ]; then
    echo "[ORCA] Generating self-signed ECDSA P-256 cert..."
    IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    HOST=$(hostname)
    SAN="IP:${IP},DNS:${HOST},DNS:orca-backend,DNS:localhost"
    if [ -n "$EXTERNAL_HOST" ]; then
        if echo "$EXTERNAL_HOST" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
            SAN="${SAN},IP:${EXTERNAL_HOST}"
        else
            SAN="${SAN},DNS:${EXTERNAL_HOST}"
        fi
    fi
    # Backdate notBefore by a day -- confirmed live 2026-08-26 that a VM host's
    # clock running fast at generation time (later corrected by a time sync)
    # produces a cert whose own start-of-validity is hours in the future,
    # which every client then rejects as "not yet valid" until real time
    # catches up. This buffer absorbs that class of clock skew instead of
    # requiring the host clock to be exactly right at the moment of generation.
    NOT_BEFORE=$(date -u -d '-1 day' +%Y%m%d%H%M%SZ 2>/dev/null || true)
    NOT_BEFORE_ARGS=""
    if [ -n "$NOT_BEFORE" ]; then
        NOT_BEFORE_ARGS="-not_before $NOT_BEFORE"
    fi
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$KEY" -out "$CERT" -days 365 -nodes \
        -subj "/CN=orca" \
        -addext "subjectAltName=${SAN}" \
        $NOT_BEFORE_ARGS
    echo "[ORCA] Certificate generated: SAN=${SAN}"
else
    echo "[ORCA] TLS certificate exists and covers ORCA_SERVER_URL — skipping generation."
fi

# Update ClamAV signatures (non-fatal)
mkdir -p /var/lib/clamav
freshclam --quiet 2>/dev/null || echo "[ORCA] WARN: freshclam update failed, using existing signatures"

# Verify investigation working-directory mount is writable
if touch /app/cases/.orca_mount_check 2>/dev/null; then
    rm -f /app/cases/.orca_mount_check
    CASES_HOST="${CASES_DIR:-<ORCA project folder>/cases}"
    echo "[ORCA] Cases mount OK — investigation folders will be created at: ${CASES_HOST}"
else
    echo "[ORCA] WARN: /app/cases is not writable — 'Create local working directory' will not work. Set CASES_DIR in .env and restart."
fi

# Pre-warm LibreOffice so first PDF export doesn't incur 5-15s cold-start delay
echo "[ORCA] Pre-warming LibreOffice..."
printf '<html><body>ORCA</body></html>' > /tmp/orca_warmup.html
HOME=/tmp soffice --headless --convert-to pdf --outdir /tmp /tmp/orca_warmup.html 2>/dev/null || true
rm -f /tmp/orca_warmup.html /tmp/orca_warmup.pdf
echo "[ORCA] LibreOffice ready."

exec "$@"
