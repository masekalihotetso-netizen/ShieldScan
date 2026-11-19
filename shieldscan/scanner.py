"""Orchestrates a scan: intake -> analysis -> fusion -> report.

The original file is never modified. Analysis runs on a private working copy and the
SHA-256 of the original is compared before and after to prove integrity."""
import os
import shutil
import tempfile
import time
import uuid
import base64
import email
import email.policy

from . import config
from .utils import sha256_file, sniff_kind

ADVICE = {
    "High": ["Do not open the file or click any links.",
             "Verify the request with the supposed sender on a phone number you already know (out-of-band).",
             "Report the item to IT / security and quarantine it."],
    "Medium": ["Treat with caution: do not act on payment or credential requests until verified.",
               "Check the sender address and link destinations manually before proceeding."],
    "Low": ["No strong indicators found. Automated checks are probabilistic, so stay alert to unusual requests."],
}


def level_for(score):
    for t, name in config.LEVELS:
        if score >= t:
            return name
    return "Low"


class UnsupportedFile(Exception):
    pass


def classify(path, filename):
    ext = os.path.splitext(filename)[1].lower()
    kind = sniff_kind(path, ext)
    if kind is None:
        if ext in config.TEXT_EXT:
            kind = "text"
        elif ext in config.IMAGE_EXT:
            kind = "image"
        elif ext in config.AUDIO_EXT:
            kind = "audio"
        elif ext in config.VIDEO_EXT:
            kind = "video"
    if kind is None:
        # unknown signature: treat printable content as text
        with open(path, "rb") as f:
            head = f.read(2048)
        if head and sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127) / len(head) > 0.85:
            kind = "text"
    if kind is None:
        raise UnsupportedFile(f"Unsupported file type '{ext or 'unknown'}'. Supported: text, image, video, audio.")
    mismatch = None
    expect = ("text" if ext in config.TEXT_EXT else "image" if ext in config.IMAGE_EXT else
              "audio" if ext in config.AUDIO_EXT else "video" if ext in config.VIDEO_EXT else None)
    if expect and expect != kind and not (expect in ("audio", "video") and kind in ("audio", "video")):
        mismatch = f"File extension '{ext}' suggests {expect} but the content is {kind} (possible disguise)"
    return kind, mismatch



def _preview(path, filename, kind):
    """Build a safe, bounded preview for the Scanner result.

    The preview is informational only. Original files are never served back by Flask;
    text is rendered as text and email images are returned as data URLs with a strict
    size/count cap.
    """
    ext = os.path.splitext(filename)[1].lower()
    if kind == "text":
        try:
            raw = open(path, "rb").read(512 * 1024)
            subject = ""
            body = raw.decode("utf-8", errors="replace")
            images = []
            if ext == ".eml" or b"\nfrom:" in raw[:5000].lower() or raw[:5].lower() == b"from:":
                msg = email.message_from_bytes(raw, policy=email.policy.default)
                subject = str(msg.get("subject", ""))
                body_part = msg.get_body(preferencelist=("plain", "html"))
                if body_part is not None:
                    body = body_part.get_content()
                    if body_part.get_content_type() == "text/html":
                        import re as _re
                        body = _re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>", " ", body, flags=_re.I)
                        body = _re.sub(r"<[^>]+>", " ", body)
                        body = _re.sub(r"\s+", " ", body).strip()
                total = 0
                for part in msg.walk():
                    if part.is_multipart() or not part.get_content_type().startswith("image/"):
                        continue
                    data = part.get_payload(decode=True) or b""
                    if not data or len(data) > 2 * 1024 * 1024 or total + len(data) > 5 * 1024 * 1024:
                        continue
                    total += len(data)
                    images.append({
                        "filename": part.get_filename() or "inline-image",
                        "mime": part.get_content_type(),
                        "data_url": "data:%s;base64,%s" % (part.get_content_type(), base64.b64encode(data).decode("ascii")),
                    })
            return {"type": "text", "subject": subject, "body": body[:20000], "images": images[:8]}
        except Exception:
            return None
    return None

def scan_file(path, filename, keep_copy=False):
    t0 = time.perf_counter()
    size = os.path.getsize(path)
    h_before = sha256_file(path)
    work = tempfile.mkdtemp(prefix="shield_")
    try:
        copy = os.path.join(work, "sample" + os.path.splitext(filename)[1].lower())
        shutil.copy2(path, copy)
        kind, mismatch = classify(copy, filename)
        steps = ["Intake: SHA-256 fingerprint, file-signature check, isolated working copy"]
        if kind == "text":
            from . import text_detector
            with open(copy, "rb") as f:
                res = text_detector.analyse(f.read(), filename)
        elif kind == "image":
            from . import image_detector
            res = image_detector.analyse(copy)
        elif kind == "audio":
            from . import audio_detector
            res = audio_detector.analyse(copy)
        else:
            from . import video_detector
            res = video_detector.analyse(copy)
        steps += res["steps"]
        evidence = list(res["evidence"])
        risk = res["risk"]
        if mismatch:
            evidence.insert(0, ("high", mismatch)); risk = max(risk, 0.75)
            steps.append("Extension-vs-content mismatch check")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    h_after = sha256_file(path)
    score = int(round(risk * 100))
    level = level_for(score)
    order = {"high": 0, "medium": 1, "info": 2}
    evidence.sort(key=lambda e: order.get(e[0], 3))
    return {
        "id": uuid.uuid4().hex[:10], "filename": filename, "kind": kind, "size_bytes": size,
        "score": score, "level": level,
        "evidence": [{"severity": s, "text": t} for s, t in evidence],
        "recommendations": ADVICE[level], "steps": steps, "models": res["models"],
        "details": {**res.get("details", {}), **({"preview": _preview(path, filename, kind)} if _preview(path, filename, kind) else {})},
        "ai_generated_likelihood": res.get("ai_generated_likelihood"),
        "integrity": {"sha256_before": h_before, "sha256_after": h_after, "unchanged": h_before == h_after},
        "elapsed_s": round(time.perf_counter() - t0, 3),
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
