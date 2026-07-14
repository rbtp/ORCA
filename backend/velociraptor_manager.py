"""
velociraptor_manager.py
Manages the Velociraptor GUI process lifecycle for ORCA.
"""

import os
import signal
import subprocess
import threading
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import Response

from config import cfg

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

VELO_BINARY    = str(cfg.VR_EXE_LOCAL)
VELO_CONFIG    = Path(VELO_BINARY).parent / "server.config.yaml"
_gui_port: int = 8889  # updated after config is read
def _get_gui_port() -> int:
    """Read the GUI port from the generated config, fall back to 8889."""
    try:
        import yaml
        with open(VELO_CONFIG) as f:
            cfg_data = yaml.safe_load(f)
        # Velociraptor stores GUI bind address under GUI.bind_address or similar
        bind = (cfg_data.get("GUI", {}) or {}).get("bind_port")             or (cfg_data.get("gui", {}) or {}).get("bind_port")             or 8889
        return int(bind)
    except Exception:
        return 8889

# ---------------------------------------------------------------------------
# State — protected by a threading.Lock so concurrent requests can't race
# ---------------------------------------------------------------------------

_lock    = threading.Lock()
_process: Optional[subprocess.Popen] = None
_log_lines: list[str] = []


def _log(msg: str):
    print(f"[velo] {msg}", flush=True)
    _log_lines.append(msg)
    if len(_log_lines) > 200:
        _log_lines.pop(0)


def _is_running() -> bool:
    return _process is not None and _process.poll() is None


def get_status() -> dict:
    return {
        "running":       _is_running(),
        "pid":           _process.pid if _is_running() else None,
        "port":          _gui_port if _is_running() else None,
        "config_exists": VELO_CONFIG.exists(),
        "log":           _log_lines[-50:],
    }


def _ensure_config() -> bool:
    if VELO_CONFIG.exists():
        return True
    _log(f"Config not found at {VELO_CONFIG}, generating...")
    try:
        r = subprocess.run(
            [VELO_BINARY, "config", "generate"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            _log(f"Config generation failed: {r.stderr.strip()}")
            return False
        # config generate writes yaml to stdout — save it
        VELO_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        VELO_CONFIG.write_text(r.stdout, encoding="utf-8")
        _log(f"Config written to {VELO_CONFIG}.")
        return True
    except Exception as e:
        _log(f"Config generation exception: {e}")
        return False


def start_velociraptor() -> dict:
    global _process
    with _lock:
        if _is_running():
            return {"ok": True, "message": "Already running", **get_status()}

        global _gui_port
        if not _ensure_config():
            raise HTTPException(status_code=500, detail="Failed to generate Velociraptor config")
        _gui_port = _get_gui_port()

        _log(f"Starting Velociraptor GUI on port {_gui_port}...")
        try:
            import time
            _process = subprocess.Popen(
                [VELO_BINARY, "--config", str(VELO_CONFIG), "gui", "--nobrowser"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
            time.sleep(1)
            if _process.poll() is not None:
                out = _process.stdout.read().decode(errors="replace") if _process.stdout else ""
                _process = None
                _log(f"Velociraptor exited immediately: {out[:500]}")
                raise HTTPException(status_code=500, detail=f"Velociraptor exited immediately: {out[:300]}")
            _log(f"Velociraptor PID {_process.pid} started.")
            return {"ok": True, "message": "Started", **get_status()}
        except HTTPException:
            raise
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail=f"Binary not found: {VELO_BINARY}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


def stop_velociraptor() -> dict:
    global _process
    with _lock:
        if not _is_running():
            _process = None
            return {"ok": True, "message": "Not running", **get_status()}

        _log(f"Stopping Velociraptor PID {_process.pid}...")
        try:
            if os.name == "nt":
                subprocess.call(
                    ["taskkill", "/F", "/T", "/PID", str(_process.pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            else:
                os.killpg(os.getpgid(_process.pid), signal.SIGTERM)
            _process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _process.kill()
        except Exception as e:
            _log(f"Stop error: {e}")
        finally:
            _process = None

        _log("Velociraptor stopped.")
        return {"ok": True, "message": "Stopped", **get_status()}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/velociraptor", tags=["velociraptor"])


@router.post("/start")
def api_start():
    return start_velociraptor()


@router.post("/stop")
def api_stop():
    return stop_velociraptor()


@router.get("/status")
def api_status():
    return get_status()


# ---------------------------------------------------------------------------
# Reverse proxy — strips X-Frame-Options so iframe embedding works
# ---------------------------------------------------------------------------

@router.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(path: str, request: Request):
    if not _is_running():
        raise HTTPException(status_code=503, detail="Velociraptor is not running")

    target = f"https://127.0.0.1:{_gui_port}/{path}"
    if request.url.query:
        target += f"?{request.url.query}"

    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length", "transfer-encoding")}

    # verify=False is intentional: Velociraptor manages its own self-signed cert; this is localhost-only
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target,
                headers=headers,
                content=await request.body(),
            )
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="Cannot connect to Velociraptor GUI")

    strip = {"x-frame-options", "content-security-policy", "x-content-type-options"}
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in strip}

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=resp_headers,
        media_type=resp.headers.get("content-type"),
    )