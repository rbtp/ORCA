#!/bin/sh
set -e

CERT_DIR=/app/certs
CERT=$CERT_DIR/orca.crt
KEY=$CERT_DIR/orca.key

mkdir -p "$CERT_DIR"

# Generate self-signed ECDSA P-256 cert on first boot
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[ORCA] No TLS certificate found — generating self-signed ECDSA P-256 cert..."
    IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    HOST=$(hostname)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$KEY" -out "$CERT" -days 365 -nodes \
        -subj "/CN=orca" \
        -addext "subjectAltName=IP:${IP},DNS:${HOST},DNS:orca-backend,DNS:localhost"
    echo "[ORCA] Certificate generated: IP=${IP}, hostname=${HOST}"
else
    echo "[ORCA] TLS certificate exists — skipping generation."
fi

# Update ClamAV signatures (non-fatal)
mkdir -p /var/lib/clamav
freshclam --quiet 2>/dev/null || echo "[ORCA] WARN: freshclam update failed, using existing signatures"

# Pre-warm LibreOffice so first PDF export doesn't incur 5-15s cold-start delay
echo "[ORCA] Pre-warming LibreOffice..."
printf '<html><body>ORCA</body></html>' > /tmp/orca_warmup.html
HOME=/tmp soffice --headless --convert-to pdf --outdir /tmp /tmp/orca_warmup.html 2>/dev/null || true
rm -f /tmp/orca_warmup.html /tmp/orca_warmup.pdf
echo "[ORCA] LibreOffice ready."

exec "$@"
