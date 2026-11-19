
"""Live mailbox connection (IMAP over SSL) and whole-message scanning.

Safety properties:
- READ-ONLY: the folder is opened with readonly=True and messages are fetched
  with BODY.PEEK, so nothing is marked as read, moved or deleted.
- Credentials live only in memory for the duration of one request. They are
  never written to disk, never logged and never included in a report.
- Attachments are written to a private temp folder, scanned, then removed.
"""

import email
import email.policy
import imaplib
import os
import re
import shutil
import socket
import ssl
import tempfile

from html import unescape
from email.utils import parseaddr

from . import config
from .scanner import scan_file, level_for, UnsupportedFile


PRESETS = {
    "gmail": {
        "host": "imap.gmail.com",
        "label": "Gmail (needs an App Password)"
    },
    "outlook": {
        "host": "outlook.office365.com",
        "label": "Outlook / Microsoft 365"
    },
    "yahoo": {
        "host": "imap.mail.yahoo.com",
        "label": "Yahoo (needs an App Password)"
    },
    "icloud": {
        "host": "imap.mail.me.com",
        "label": "iCloud (needs an App-Specific Password)"
    },
    "custom": {
        "host": "",
        "label": "Other IMAP server"
    },
}

HOST_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
)

MAX_MSG_BYTES = 30 * 1024 * 1024
MAX_ATTACH = 10

HELP = {
    "gmail": (
        "Gmail rejects your normal password for IMAP. Turn on 2-Step "
        "Verification, create an App Password (Google Account > Security > "
        "App passwords) and enter that 16-character code. IMAP must be "
        "enabled in Gmail settings."
    ),
    "outlook": (
        "Microsoft has switched off password sign-in for many Outlook/Hotmail "
        "accounts. Work/school accounts may need IMAP enabled by the "
        "administrator; if sign-in keeps failing, export the message as .eml "
        "and drop it into the Scanner tab."
    ),
    "yahoo": (
        "Yahoo requires an App Password (Account Security > Generate app password)."
    ),
    "icloud": (
        "iCloud requires an app-specific password "
        "(appleid.apple.com > Sign-In and Security)."
    ),
}


class MailError(Exception):
    pass


def resolve_host(provider, host):
    if provider in PRESETS and provider != "custom":
        return PRESETS[provider]["host"]

    host = (host or "").strip().lower()

    if not HOST_RE.match(host):
        raise MailError(
            "Enter a valid IMAP server name, e.g. imap.example.com"
        )

    return host


def fetch_messages(
    host,
    user,
    password,
    folder="INBOX",
    limit=15,
    provider="custom"
):
    """Return newest messages as (uid, raw_bytes, skipped_reason)."""

    limit = max(1, min(int(limit), 30))

    try:
        box = imaplib.IMAP4_SSL(
            host,
            993,
            ssl_context=ssl.create_default_context(),
            timeout=30
        )
    except (socket.gaierror, socket.timeout, OSError, ssl.SSLError) as e:
        raise MailError(
            f"Could not reach {host} on the secure IMAP port (993): "
            f"{type(e).__name__}"
        )

    out = []

    try:
        try:
            box.login(user, password)
        except imaplib.IMAP4.error:
            raise MailError(
                "Sign-in was refused by the mail server. "
                + HELP.get(
                    provider,
                    "Check the address and password, and that IMAP is enabled."
                )
            )

        typ, _ = box.select(
            '"' + folder.replace('"', "") + '"',
            readonly=True
        )

        if typ != "OK":
            raise MailError(f"Folder '{folder}' was not found.")

        typ, data = box.uid("SEARCH", None, "ALL")

        if typ != "OK" or not data:
            return out

        uids = (data[0] or b"").split()[-limit:][::-1]

        for uid in uids:
            typ, sz = box.uid("FETCH", uid, "(RFC822.SIZE)")

            size_data = sz[0] if sz and sz[0] else b""
            m = re.search(rb"RFC822\.SIZE (\d+)", size_data)

            if m and int(m.group(1)) > MAX_MSG_BYTES:
                out.append((
                    uid.decode(),
                    None,
                    f"Skipped: message larger than "
                    f"{MAX_MSG_BYTES // 1048576} MB"
                ))
                continue

            typ, msgdata = box.uid(
                "FETCH",
                uid,
                "(BODY.PEEK[])"
            )

            raw = next(
                (
                    p[1]
                    for p in msgdata
                    if isinstance(p, tuple)
                ),
                None
            )

            out.append((
                uid.decode(),
                raw,
                None if raw else "Skipped: could not download"
            ))

    finally:
        try:
            box.logout()
        except Exception:
            pass

    return out


def auth_status(msg):
    """Interpret SPF/DKIM/DMARC from Authentication-Results."""

    ar = (
        msg.get_all("authentication-results") or [""]
    )[0].lower()

    spf = (
        re.search(r"spf=(\w+)", ar)
        or [None, None]
    )[1]

    if not spf:
        spf = (
            re.search(
                r"^(\w+)",
                (msg.get("received-spf") or "").strip().lower()
            )
            or [None, None]
        )[1]

    dkim = (
        re.search(r"dkim=(\w+)", ar)
        or [None, None]
    )[1]

    dmarc = (
        re.search(r"dmarc=(\w+)", ar)
        or [None, None]
    )[1]

    vals = [v for v in (spf, dkim, dmarc) if v]

    if not vals:
        state = "unknown"
    elif any(v in ("fail", "softfail", "permerror") for v in vals):
        state = "failed"
    elif dmarc == "pass" or (spf == "pass" and dkim == "pass"):
        state = "verified"
    else:
        state = "partial"

    return {
        "state": state,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }


def extract_email_body(msg):
    """
    Extract readable text from an email.

    Plain text is preferred. HTML is converted to readable text when
    a plain-text version is not available. Attachments are excluded.
    """

    plain_parts = []
    html_parts = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        if part.get_filename():
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()

            if not isinstance(content, str):
                continue

            if content_type == "text/plain":
                if content.strip():
                    plain_parts.append(content.strip())

            else:
                # Remove scripts and styles before extracting text.
                content = re.sub(
                    r"<(script|style)\b[^>]*>.*?</\1>",
                    "",
                    content,
                    flags=re.IGNORECASE | re.DOTALL
                )

                # Preserve basic paragraph breaks.
                content = re.sub(
                    r"<br\s*/?>|</p>|</div>|</li>|</tr>",
                    "\n",
                    content,
                    flags=re.IGNORECASE
                )

                # Remove remaining HTML tags.
                content = re.sub(r"<[^>]+>", " ", content)

                # Decode HTML entities.
                content = unescape(content)

                # Clean excessive whitespace.
                content = re.sub(
                    r"[ \t]+",
                    " ",
                    content
                )

                content = re.sub(
                    r"\n[ \t]*\n+",
                    "\n\n",
                    content
                ).strip()

                if content:
                    html_parts.append(content)

        except Exception:
            continue

    if plain_parts:
        return "\n\n".join(plain_parts), "text/plain"

    if html_parts:
        return "\n\n".join(html_parts), "text/html"

    return "No readable message content was found.", "unknown"


def _attachments(msg):
    """Return downloadable attachments for scanning."""

    n = 0

    for part in msg.walk():
        if part.is_multipart():
            continue

        ctype = part.get_content_type()
        fname = part.get_filename()

        is_body = ctype in ("text/plain", "text/html") and not fname

        if is_body or ctype.startswith("message/"):
            continue

        yield (
            part,
            ctype,
            fname or f"inline-{n}.{ctype.split('/')[-1]}"
        )

        n += 1


def scan_message(raw):
    """Scan one email and its attachments."""

    work = tempfile.mkdtemp(prefix="shield_mail_")

    try:
        p = os.path.join(work, "message.eml")

        with open(p, "wb") as f:
            f.write(raw)

        rep = scan_file(p, "message.eml")

        msg = email.message_from_bytes(
            raw,
            policy=email.policy.default
        )

        # Extract the actual email content.
        body, body_content_type = extract_email_body(msg)

        auth = auth_status(msg)

        name, addr = parseaddr(str(msg.get("from", "")))

        atts = []
        skipped = 0

        for part, ctype, fname in _attachments(msg):

            if len(atts) >= MAX_ATTACH:
                skipped += 1
                continue

            safe = re.sub(
                r"[^A-Za-z0-9._-]",
                "_",
                os.path.basename(fname)
            )[:80] or "attachment"

            ap = os.path.join(
                work,
                f"att{len(atts)}_{safe}"
            )

            try:
                data = part.get_payload(decode=True) or b""

                with open(ap, "wb") as f:
                    f.write(data)

                r = scan_file(ap, fname)

                atts.append({
                    "filename": fname,
                    "type": ctype,
                    "kind": r["kind"],
                    "size_bytes": len(data),
                    "scanned": True,
                    "score": r["score"],
                    "level": r["level"],
                    "evidence": r["evidence"][:4],
                    "report_id": r["id"],
                    "sha256": r["integrity"]["sha256_before"]
                })

            except UnsupportedFile:
                ext = os.path.splitext(fname)[1].lower()

                risky = ext in (
                    ".exe", ".scr", ".js", ".vbs", ".iso",
                    ".lnk", ".bat", ".docm", ".xlsm", ".jar", ".ps1"
                )

                atts.append({
                    "filename": fname,
                    "type": ctype,
                    "kind": "other",
                    "size_bytes": len(data),
                    "scanned": False,
                    "score": 90 if risky else 0,
                    "level": "High" if risky else "Low",
                    "evidence": [{
                        "severity": "high" if risky else "info",
                        "text": (
                            "Executable/macro attachment type"
                            if risky else
                            "File type not analysed by ShieldScan (open with care)"
                        )
                    }]
                })

            except Exception as e:
                atts.append({
                    "filename": fname,
                    "type": ctype,
                    "kind": "other",
                    "size_bytes": 0,
                    "scanned": False,
                    "score": 0,
                    "level": "Low",
                    "evidence": [{
                        "severity": "info",
                        "text": f"Could not analyse: {type(e).__name__}"
                    }]
                })

    finally:
        shutil.rmtree(work, ignore_errors=True)

    att_max = max(
        [a["score"] for a in atts],
        default=0
    )

    score = max(
        rep["score"],
        int(round(att_max * 0.9))
    )

    level = level_for(score)

    evidence = list(rep["evidence"])

    for a in atts:
        if a["score"] >= 40:
            evidence.insert(0, {
                "severity": "high" if a["score"] >= 70 else "medium",
                "text": (
                    f"Attachment '{a['filename']}' scored "
                    f"{a['score']}/100: "
                    + (
                        a["evidence"][0]["text"]
                        if a["evidence"]
                        else a["kind"]
                    )
                )
            })

    if skipped:
        evidence.append({
            "severity": "info",
            "text": (
                f"{skipped} further attachment(s) not scanned "
                f"(limit {MAX_ATTACH})"
            )
        })

    ai_media = [
        a["filename"]
        for a in atts
        if a["kind"] in ("image", "audio", "video")
        and a["score"] >= 50
    ]

    ai_text = rep.get("ai_generated_likelihood")

    if auth["state"] == "failed" or level == "High":
        verdict = "fake"
        vtxt = "Likely fake or malicious"

    elif level == "Medium" or ai_media:
        verdict = "suspicious"
        vtxt = "Suspicious - verify before acting"

    elif auth["state"] == "verified":
        verdict = "genuine"
        vtxt = "Looks genuine - sender verified"

    else:
        verdict = "unverified"
        vtxt = "No warning signs, but sender could not be verified"

    d = rep.get("details", {})

    recommendations = (
        rep["recommendations"]
        if level != "Low"
        else (
            [
                "Sender authentication passed and no red flags were found. "
                "Still verify unusual money or password requests by phone."
            ]
            if verdict == "genuine"
            else rep["recommendations"]
        )
    )

    return {
        "id": rep["id"],
        "uid": None,
        "verdict": verdict,
        "verdict_text": vtxt,
        "score": score,
        "level": level,
        "subject": d.get("subject") or "(no subject)",

        "from_name": name,
        "from_addr": addr,
        "date": str(msg.get("date", "")),

        # Actual email body.
        "body": body,
        "body_content_type": body_content_type,

        "auth": auth,
        "ai_text_likelihood": ai_text,
        "ai_media_flagged": ai_media,
        "evidence": evidence,
        "attachments": atts,
        "recommendations": recommendations,
        "models": rep["models"],
        "scanned_at": rep["scanned_at"],
        "filename": d.get("subject") or "message.eml",
        "kind": "email",
        "size_bytes": len(raw),
        "integrity": rep["integrity"],
        "steps": rep["steps"],
        "details": d
    }


def scan_mailbox(
    provider,
    host,
    user,
    password,
    folder="INBOX",
    limit=15
):
    h = resolve_host(provider, host)

    if not user or not password:
        raise MailError("Enter your email address and password.")

    results = []

    for uid, raw, why in fetch_messages(
        h,
        user,
        password,
        folder,
        limit,
        provider
    ):

        if raw is None:
            results.append({
                "uid": uid,
                "verdict": "skipped",
                "verdict_text": why,
                "subject": why,
                "from_addr": "",
                "from_name": "",
                "score": 0,
                "level": "Low",
                "attachments": [],
                "evidence": [],
                "auth": {"state": "unknown"},
                "id": None
            })
            continue

        try:
            r = scan_message(raw)

        except Exception as e:
            r = {
                "id": None,
                "verdict": "skipped",
                "verdict_text": (
                    f"Could not analyse: {type(e).__name__}"
                ),
                "subject": "(unreadable message)",
                "from_addr": "",
                "from_name": "",
                "score": 0,
                "level": "Low",
                "attachments": [],
                "evidence": [],
                "auth": {"state": "unknown"}
            }

        r["uid"] = uid
        results.append(r)

    return results
