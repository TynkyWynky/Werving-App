from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr


def format_datetime_for_email(dt_str: str) -> str:
    """
    Input: "YYYY-MM-DD HH:MM:SS"
    Output: "DD-MM-YYYY HH:MM"
    """
    s = (dt_str or "").strip()
    if len(s) >= 16:
        date_part = s[:10]          # YYYY-MM-DD
        time_part = s[11:16]        # HH:MM
        y, m, d = date_part.split("-")
        return f"{d}-{m}-{y} {time_part}"
    return s


def send_email(to_email: str, subject: str, text_body: str, html_body: str | None = None) -> tuple[bool, str]:
    """
    Returns: (success, error_message)
    Configure via env:
      SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
      SMTP_FROM_EMAIL, SMTP_FROM_NAME, SMTP_USE_TLS (1/0)
    """
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "").strip()
    from_email = os.environ.get("SMTP_FROM_EMAIL", "").strip() or username
    from_name = os.environ.get("SMTP_FROM_NAME", "Werving App").strip()
    use_tls = os.environ.get("SMTP_USE_TLS", "1").strip() == "1"

    if not host or not from_email:
        return (False, "SMTP_HOST/SMTP_FROM_EMAIL niet ingesteld")

    msg = EmailMessage()
    msg["From"] = formataddr((from_name, from_email))
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        if port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context) as server:
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port) as server:
                server.ehlo()
                if use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                if username and password:
                    server.login(username, password)
                server.send_message(msg)

        return (True, "")
    except Exception as e:
        return (False, str(e))
