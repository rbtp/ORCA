import os
import sys
import socket
import subprocess
import threading
import time
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from auth_utils import get_current_user, require_admin

router = APIRouter(prefix="/api/network", tags=["network"])

CERT_PATH = os.environ.get("TLS_CERT_PATH", "/app/certs/orca.crt")
KEY_PATH  = os.environ.get("TLS_KEY_PATH",  "/app/certs/orca.key")


def _get_server_identity():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    hostname = socket.gethostname()
    return ip, hostname


def _parse_cert_info(cert_path: str) -> dict:
    info = {"cert_exists": True, "sans": [], "key_type": "Unknown",
            "not_after": None, "days_remaining": None}

    # Expiry
    r = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.startswith("notAfter="):
            raw = line[len("notAfter="):].strip()
            try:
                dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
                info["not_after"] = dt.isoformat()
                info["days_remaining"] = (dt - datetime.utcnow()).days
            except Exception:
                info["not_after"] = raw

    # SANs
    r = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectAltName"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        line = line.strip()
        if "IP Address:" in line or "DNS:" in line:
            for part in line.split(","):
                part = part.strip()
                if part.startswith("IP Address:"):
                    info["sans"].append("IP:" + part[len("IP Address:"):].strip())
                elif part.startswith("DNS:"):
                    info["sans"].append(part.strip())

    # Key type (check -text output)
    r = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-text"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if "Public Key Algorithm" in line:
            if "ecPublicKey" in line or "EC" in line:
                info["key_type"] = "ECDSA"
            elif "rsaEncryption" in line:
                info["key_type"] = "RSA"
        if "P-256" in line or "prime256v1" in line:
            info["key_type"] = "ECDSA P-256"
            break

    return info


def _restart_after_delay(delay: float = 2.0):
    time.sleep(delay)
    os.execv(sys.executable, [sys.executable] + sys.argv)


@router.get("/cert-info")
async def cert_info(current_user: dict = Depends(get_current_user)):
    if not os.path.exists(CERT_PATH):
        return {"cert_exists": False, "sans": [], "key_type": None,
                "not_after": None, "days_remaining": None}
    try:
        return _parse_cert_info(CERT_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read cert: {e}")


@router.get("/detected-identity")
async def detected_identity(current_user: dict = Depends(get_current_user)):
    ip, hostname = _get_server_identity()
    return {"ip": ip, "hostname": hostname}


@router.post("/regenerate-cert")
async def regenerate_cert(current_user: dict = Depends(require_admin)):

    ip, hostname = _get_server_identity()
    san = f"IP:{ip},DNS:{hostname},DNS:orca-backend,DNS:localhost"
    cert_dir = os.path.dirname(CERT_PATH)
    os.makedirs(cert_dir, exist_ok=True)

    result = subprocess.run([
        "openssl", "req", "-x509",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-keyout", KEY_PATH, "-out", CERT_PATH,
        "-days", "365", "-nodes",
        "-subj", "/CN=orca",
        "-addext", f"subjectAltName={san}",
    ], capture_output=True, text=True)

    if result.returncode != 0:
        raise HTTPException(status_code=500,
                            detail=f"openssl failed: {result.stderr.strip()}")

    # Restart backend so uvicorn picks up the new cert (5-second delay — allows response to
    # reach the client and gives nginx time to notice the connection drop before reconnecting)
    t = threading.Thread(target=_restart_after_delay, args=(5.0,), daemon=True)
    t.start()

    return {
        "success": True,
        "ip": ip,
        "hostname": hostname,
        "san": san,
        "restart_in_seconds": 5,
        "message": "Certificate regenerated. Backend restarting in 5s — page will reload automatically.",
    }
