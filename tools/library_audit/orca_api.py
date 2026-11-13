"""Small API client used by score_atomics.py (login cookie, req/js/check helpers).

End-to-end functional test for an ORCA install, driven through nginx exactly
like the browser (HttpOnly session cookie, relative /api paths).

usage: python e2e.py BASE_URL ADMIN_USER ADMIN_PASSWORD BACKEND_CONTAINER
Every check prints PASS/FAIL; any HTTP 5xx anywhere is a FAIL.
"""
import http.cookiejar
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE, USER, PWD, BACKEND = sys.argv[1:5]
CTX = ssl._create_unverified_context()
JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                     urllib.request.HTTPCookieProcessor(JAR))
RESULTS = []
SERVER_ERRORS = []


def req(method, path, body=None, raw=None, ctype=None, timeout=120, stream=False):
    url = BASE + path
    data, headers = None, {}
    if body is not None:
        data = json.dumps(body).encode(); headers["Content-Type"] = "application/json"
    elif raw is not None:
        data = raw; headers["Content-Type"] = ctype
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        resp = OPENER.open(r, timeout=timeout)
        status = resp.status
        content = resp if stream else resp.read()
    except urllib.error.HTTPError as e:
        status, content = e.code, e.read()
    except Exception as e:
        status, content = 0, str(e).encode()
    if status >= 500 or status == 0:
        SERVER_ERRORS.append(f"{method} {path} -> {status} {content[:200] if isinstance(content, bytes) else ''}")
    return status, content


def js(content):
    try:
        return json.loads(content)
    except Exception:
        return None


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not ok else ""), flush=True)
    return ok


def sse(path, body=None, method="POST", timeout=900, done_types=("done", "complete", "error"), max_events=100000):
    """Read an SSE stream; return list of parsed events."""
    status, resp = req(method, path, body=body, timeout=timeout, stream=True)
    events = []
    if status != 200:
        return status, events
    deadline = time.time() + timeout
    for line in resp:
        line = line.decode(errors="replace").strip()
        if line.startswith("data:"):
            ev = js(line[5:].strip())
            if ev is not None:
                events.append(ev)
                if isinstance(ev, dict) and ev.get("type") in done_types:
                    break
        if time.time() > deadline or len(events) >= max_events:
            break
    resp.close()
    return status, events


def dexec(*cmd):
    return subprocess.run(["docker", "exec", BACKEND, *cmd], capture_output=True, text=True)


