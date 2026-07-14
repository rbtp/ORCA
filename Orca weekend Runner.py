"""
orca_weekend_runner.py
Runs Claude Code sessions for the ORCA containerization task,
automatically resuming every 5 hours when tokens refresh.

Usage:
    python orca_weekend_runner.py

Requirements:
    pip install anthropic  (just for reference — claude CLI must be installed)
    Claude Code must be installed: npm install -g @anthropic-ai/claude-code
"""

import subprocess
import time
import sys
import os
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
PROJECT_DIR     = r"C:\Users\Sentinel\Desktop\Tests\ORCAWEB"
INITIAL_PROMPT  = "CONTAINERIZATION_PROMPT.md"
RESUME_PROMPT   = "RESUME_PROMPT.txt"
TOKEN_REFRESH_H = 5        # hours between token refreshes
BUFFER_MIN      = 10       # extra minutes to wait after refresh
MAX_SESSIONS    = 20       # safety limit
LOG_DIR         = "claude_logs"

# ── Resume prompt written to file ─────────────────────────────────────────────
RESUME_TEXT = """
Continue the ORCA containerization task.

1. Read CLAUDE.md to see what has been completed and what is next
2. Read CONTAINERIZATION_PROMPT.md for the full spec
3. Pick up from "Next Step" in CLAUDE.md
4. Do NOT redo completed steps
5. Update CLAUDE.md after each step
6. When fully complete, write exactly: TASK COMPLETE
"""

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(os.path.join(PROJECT_DIR, LOG_DIR, "runner.log"), "a") as f:
        f.write(line + "\n")

def run_session(session_num, prompt_file):
    """Run a single Claude Code session."""
    log(f"Starting session {session_num}")
    
    prompt_path = os.path.join(PROJECT_DIR, prompt_file)
    if not os.path.exists(prompt_path):
        log(f"ERROR: Prompt file not found: {prompt_path}")
        return False, ""

    with open(prompt_path, "r") as f:
        prompt_text = f.read()

    log_file = os.path.join(PROJECT_DIR, LOG_DIR, f"session_{session_num}.txt")

    try:
        result = subprocess.run(
            [
                "claude",
                "--dangerously-skip-permissions",  # skip confirmation prompts
                "-p", prompt_text                  # non-interactive mode
            ],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=18000  # 5 hour hard timeout
        )

        output = result.stdout + result.stderr

        # Save session log
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(f"=== Session {session_num} ===\n")
            f.write(f"Exit code: {result.returncode}\n\n")
            f.write(output)

        log(f"Session {session_num} ended (exit code {result.returncode})")
        
        complete = "TASK COMPLETE" in output
        return complete, output

    except subprocess.TimeoutExpired:
        log(f"Session {session_num} timed out after 5 hours")
        return False, ""
    except FileNotFoundError:
        log("ERROR: 'claude' command not found. Install Claude Code: npm install -g @anthropic-ai/claude-code")
        sys.exit(1)

def main():
    # Setup
    os.makedirs(os.path.join(PROJECT_DIR, LOG_DIR), exist_ok=True)

    # Write resume prompt file
    with open(os.path.join(PROJECT_DIR, RESUME_PROMPT), "w") as f:
        f.write(RESUME_TEXT)

    log("=" * 60)
    log("ORCA Weekend Runner started")
    log(f"Project: {PROJECT_DIR}")
    log(f"Token refresh interval: {TOKEN_REFRESH_H}h + {BUFFER_MIN}min buffer")
    log("=" * 60)

    wait_seconds = (TOKEN_REFRESH_H * 60 + BUFFER_MIN) * 60

    for session_num in range(1, MAX_SESSIONS + 1):
        # First session uses full prompt, subsequent use resume
        prompt_file = INITIAL_PROMPT if session_num == 1 else RESUME_PROMPT

        complete, output = run_session(session_num, prompt_file)

        if complete:
            log("=" * 60)
            log("TASK COMPLETE — Containerization finished!")
            log(f"Total sessions: {session_num}")
            log("Check DEPLOY.md for deployment instructions")
            log("=" * 60)
            break

        if session_num >= MAX_SESSIONS:
            log(f"Reached max sessions ({MAX_SESSIONS}). Stopping.")
            break

        # Wait for token refresh
        resume_time = datetime.fromtimestamp(time.time() + wait_seconds)
        log(f"Waiting {TOKEN_REFRESH_H}h {BUFFER_MIN}min for token refresh...")
        log(f"Next session at: {resume_time.strftime('%Y-%m-%d %H:%M:%S')}")
        time.sleep(wait_seconds)

    log("Runner finished.")

if __name__ == "__main__":
    main()