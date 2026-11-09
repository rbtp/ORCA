"""
email_utils.py — optional SMTP email delivery for account enrollment and
password reset links.

Deliberately optional, not required: ORCA runs in both connected and fully
airgapped environments (no outbound mail relay at all in the latter), so
every caller of send_email() must already have a working fallback --
showing the generated link directly in the admin UI for manual hand-off
(chat, in person, whatever channel is actually available) -- and treat a
False return as "couldn't send, fall back," never as an error to surface
as a failure. Configured via SMTP_* env vars; if SMTP_HOST is unset, this
module no-ops entirely and every send_email() call just returns False
immediately, no exception, no partial state.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "").strip() or SMTP_USER
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").strip().lower() not in ("false", "0", "no")

SMTP_CONFIGURED = bool(SMTP_HOST and SMTP_FROM)


def send_email(to: str, subject: str, body: str) -> bool:
    """
    Sends a plain-text email. Returns True only on a real, confirmed send;
    False for absolutely any other outcome (not configured, connection
    failure, auth failure, invalid recipient) -- never raises, so callers
    can unconditionally fall back to a manual-link flow without their own
    try/except.
    """
    if not SMTP_CONFIGURED:
        return False
    if not to:
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to], msg.as_string())
        return True
    except Exception as e:
        logger.warning("send_email to %s failed: %s", to, e)
        return False
