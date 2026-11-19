"""Email / text analysis: ML classifier + header, URL, impersonation and AI-style checks."""
import email
import email.policy
import math
import os
import re
from email import message_from_bytes
from urllib.parse import urlparse

import joblib

from .utils import clamp, ramp
from .train_text import MODEL_PATH

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "zip", "work", "info"}
BRANDS = ["microsoft", "google", "paypal", "dhl", "linkedin", "standardbank", "vodacom", "ecocash",
          "apple", "amazon", "facebook", "netflix", "office365", "outlook"]
URGENCY = ["urgent", "immediately", "within 24 hours", "asap", "right away", "act now", "final notice",
           "account will be", "suspended", "deactivated", "locked", "expires", "time sensitive", "today"]
CREDENTIAL = ["password", "verify your", "confirm your", "credentials", "login", "log in", "sign in",
              "one-time code", "otp", "pin", "bank account", "card details", "ssn"]
PAYMENT = ["wire transfer", "gift card", "payment", "invoice", "banking details", "bank details", "transfer",
           "remit", "refund", "supplier"]
SECRECY = ["confidential", "keep this between us", "discreet", "do not call", "don't call", "cannot take calls",
           "do not tell", "private matter"]
EXEC = ["ceo", "cfo", "vice-chancellor", "director", "dean", "head of department", "managing director"]
LLM_PHRASES = ["i hope this message finds you well", "i hope this email finds you well", "i wanted to reach out",
               "please do not hesitate", "i would appreciate your", "at your earliest convenience",
               "rest assured", "kindly note", "as per our conversation", "i came across your profile"]

_model = None


def _load_model():
    global _model
    if _model is None:
        import warnings
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error")          # a scikit-learn version mismatch must not be used silently
                if not os.path.exists(MODEL_PATH):
                    raise FileNotFoundError(MODEL_PATH)
                _model = joblib.load(MODEL_PATH)
        except Exception:
            from .train_text import retrain_seed
            _model = retrain_seed()
    return _model


def parse_input(raw: bytes, filename: str):
    """Return (subject, headers dict, body text, html body or '')."""
    ext = os.path.splitext(filename)[1].lower()
    headers, subject, html = {}, "", ""
    if ext == ".eml" or raw[:200].lower().find(b"\nfrom:") >= 0 or raw[:5].lower() == b"from:":
        try:
            msg = message_from_bytes(raw, policy=email.policy.default)
            headers = {}
            for k, v in msg.items():
                headers.setdefault(k.lower(), str(v))      # first (top-most) wins: added by the receiving server
            if len(msg.get_all("from") or []) > 1:
                headers["_dup_from"] = "1"
            subject = headers.get("subject", "")
            body_part = msg.get_body(preferencelist=("plain", "html"))
            body = body_part.get_content() if body_part else ""
            hp = msg.get_body(preferencelist=("html",))
            html = hp.get_content() if hp else ""
            if body_part is not None and body_part.get_content_type() == "text/html":
                body = re.sub(r"<[^>]+>", " ", body)
            atts = [p.get_filename() for p in msg.iter_attachments()]
            if atts:
                headers["_attachments"] = ", ".join(a for a in atts if a)
            return subject, headers, body, html
        except Exception:
            pass
    text = raw.decode("utf-8", errors="replace")
    if ext in (".html", ".htm"):
        html = text
        text = re.sub(r"<[^>]+>", " ", text)
    return subject, headers, text, html


def _domain(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _lev(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyse_urls(text, html):
    findings, score = [], 0.0
    urls = list(dict.fromkeys(URL_RE.findall(text + " " + html)))[:40]
    # anchor text vs href mismatch
    for href, label in re.findall(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", html, re.I | re.S):
        label = re.sub(r"<[^>]+>", "", label).strip()
        if URL_RE.match(label) and _domain(label) and _domain(href) and _domain(label) != _domain(href):
            findings.append(("high", f"Link text shows {_domain(label)} but points to {_domain(href)}"))
            score = max(score, 0.9)
    for u in urls:
        d = _domain(u)
        if not d:
            continue
        parts = d.split(".")
        reg = ".".join(parts[-2:]) if len(parts) >= 2 else d
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", d):
            findings.append(("high", f"Link uses a raw IP address: {d}")); score = max(score, 0.85)
        elif reg in SHORTENERS:
            findings.append(("medium", f"URL shortener hides the destination: {d}")); score = max(score, 0.55)
        elif d.startswith("xn--") or "xn--" in d:
            findings.append(("high", f"Punycode (possible homoglyph) domain: {d}")); score = max(score, 0.85)
        else:
            core = parts[-2] if len(parts) >= 2 else d
            norm = d.replace("-", "").replace(".", "").translate(str.maketrans("10354", "loesa"))
            hit = next((b for b in BRANDS if b in norm), None)
            if hit and not (core == hit or reg.startswith(hit + ".")):
                findings.append(("high", f"Domain {d} imitates the brand '{hit}'")); score = max(score, 0.9)
            else:
                near = next((b for b in BRANDS if 0 < _lev(core.replace("-", ""), b) <= 2 and len(core) > 4), None)
                if near:
                    findings.append(("high", f"Domain {d} is a look-alike of '{near}'")); score = max(score, 0.9)
            if parts[-1] in RISKY_TLDS:
                findings.append(("medium", f"Link uses a high-abuse top-level domain (.{parts[-1]}): {d}"))
                score = max(score, 0.5)
            if d.count(".") >= 4:
                findings.append(("medium", f"Unusually deep sub-domain chain: {d}")); score = max(score, 0.55)
        if u.lower().startswith("http://") and any(w in text.lower() for w in CREDENTIAL):
            findings.append(("medium", "Credentials requested over an unencrypted (http) link")); score = max(score, 0.6)
    return urls, findings, score


def analyse_headers(h):
    findings, score = [], 0.0
    if not h:
        return findings, score
    def addr(v):
        m = re.search(r"<([^>]+)>", v or "")
        return (m.group(1) if m else (v or "")).strip().lower()
    frm, rt, rp = addr(h.get("from")), addr(h.get("reply-to")), addr(h.get("return-path"))
    fd = frm.split("@")[-1] if "@" in frm else ""
    if rt and "@" in rt and rt.split("@")[-1] != fd:
        findings.append(("high", f"Reply-To domain ({rt.split('@')[-1]}) differs from sender domain ({fd})")); score = max(score, 0.8)
    if rp and "@" in rp and fd and rp.split("@")[-1] != fd:
        findings.append(("medium", "Return-Path domain differs from the From domain")); score = max(score, 0.5)
    if h.get("_dup_from"):
        findings.append(("high", "Message has more than one From header (spoofing technique)")); score = max(score, 0.85)
    auth = (h.get("authentication-results", "") + " " + h.get("received-spf", "")).lower()
    dmarc_ok = bool(re.search(r"dmarc=pass", auth))
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"=(\w+)", auth)
        if m and m.group(1) == "none" and dmarc_ok and mech != "dmarc":
            continue                                    # DMARC aligned on the other mechanism: fine
        if m and m.group(1) in ("fail", "softfail", "none", "permerror", "temperror"):
            findings.append(("high" if m.group(1) == "fail" else "medium", f"{mech.upper()} check result: {m.group(1)}"))
            score = max(score, 0.85 if m.group(1) == "fail" else 0.5)
    disp = re.match(r"\s*\"?([^\"<]+)\"?\s*<", h.get("from", ""))
    if disp:
        name = disp.group(1).lower()
        if any(e in name for e in EXEC) or any(b in name for b in BRANDS):
            if fd and any(fd.endswith(x) for x in ("gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me")):
                findings.append(("high", "Executive/brand display name sent from a free webmail address")); score = max(score, 0.85)
    att = h.get("_attachments", "")
    if re.search(r"\.(exe|scr|js|vbs|iso|img|lnk|bat|docm|xlsm)\b", att, re.I):
        findings.append(("high", f"Risky attachment type: {att}")); score = max(score, 0.9)
    return findings, score


def stylometry(text):
    """Weak signals of machine-generated prose. Used as a small contributor only."""
    sents = [s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if len(s.split()) > 2]
    words = re.findall(r"[A-Za-z']+", text.lower())
    if len(sents) < 4 or len(words) < 60:
        return None
    lens = [len(s.split()) for s in sents]
    mean = sum(lens) / len(lens)
    sd = math.sqrt(sum((l - mean) ** 2 for l in lens) / len(lens))
    burst = sd / mean if mean else 0
    ttr = len(set(words)) / len(words)
    low = text.lower()
    phrases = [p for p in LLM_PHRASES if p in low]
    contractions = len(re.findall(r"\b\w+'(s|t|re|ve|ll|d|m)\b", low)) / max(1, len(words))
    s = 0.45 * ramp(burst, 0.55, 0.2) + 0.2 * ramp(contractions, 0.02, 0.0) + 0.35 * clamp(len(phrases) / 2)
    return clamp(s), burst, ttr, phrases


def count_hits(low, terms):
    return [t for t in terms if t in low]


MAX_TEXT_BYTES = 1 * 1024 * 1024      # analyse the first 1 MB; phishing content is always near the top


def analyse(raw: bytes, filename: str):
    truncated = len(raw) > MAX_TEXT_BYTES
    raw = raw[:MAX_TEXT_BYTES]
    subject, headers, body, html = parse_input(raw, filename)
    full = (subject + "\n" + body).strip()
    low = full.lower()
    evidence, steps = [], []
    if truncated:
        evidence.append(("info", "Large file: the first 1 MB was analysed"))

    # 1 ML model
    ml_p = None
    m = _load_model()
    if m is not None and full:
        ml_p = float(m.predict_proba([full])[0][1])
        steps.append("TF-IDF word + character n-gram logistic-regression classifier")
        evidence.append(("high" if ml_p > .7 else "medium" if ml_p > .4 else "info",
                         f"Language model classifies the text as {ml_p*100:.0f}% likely phishing"))

    # 2 social-engineering cues
    cues = {"urgency": count_hits(low, URGENCY), "credential request": count_hits(low, CREDENTIAL),
            "payment request": count_hits(low, PAYMENT), "secrecy": count_hits(low, SECRECY)}
    cue_score = 0.0
    for name, hits in cues.items():
        if hits:
            cue_score += 0.22 if name in ("credential request", "payment request") else 0.18
            evidence.append(("medium", f"Social-engineering cue - {name}: " + ", ".join(sorted(set(hits))[:4])))
    if any(e in low for e in EXEC) and (cues["payment request"] or cues["secrecy"]):
        cue_score += 0.25
        evidence.append(("high", "Possible executive impersonation (authority + money/secrecy)"))
    cue_score = clamp(cue_score)
    steps.append("Social-engineering cue analysis (urgency, credentials, payment, secrecy, authority)")

    # 3 URLs
    urls, uf, us = analyse_urls(body, html)
    evidence += uf
    steps.append("URL analysis (look-alike and punycode domains, shorteners, raw IPs, link-text mismatch)")

    # 4 Headers
    hf, hs = analyse_headers(headers)
    evidence += hf
    if headers:
        steps.append("Header analysis (SPF/DKIM/DMARC, Reply-To and Return-Path mismatch, display-name spoofing)")

    # 5 AI-style
    sty = stylometry(body)
    ai_score = None
    if sty:
        ai_score, burst, ttr, phrases = sty
        steps.append("Stylometry (sentence-length burstiness, vocabulary, stock LLM phrasing)")
        if ai_score > 0.5:
            evidence.append(("medium", f"Text style is uniform and formulaic (burstiness {burst:.2f})"
                             + (f"; stock phrases: {', '.join(phrases[:3])}" if phrases else "")))

    # Fusion
    comps = [(0.40, ml_p if ml_p is not None else cue_score), (0.20, cue_score), (0.25, us), (0.15, hs)]
    base = sum(w * v for w, v in comps)
    hard = max(us, hs)                       # a single strong technical indicator should not be diluted
    risk = max(base, 0.85 * hard, 0.0)
    if ai_score is not None:
        risk = clamp(risk + 0.08 * ai_score * (1 if risk > 0.3 else 0.3))
    return {
        "risk": risk, "evidence": evidence, "steps": steps, "ai_generated_likelihood": ai_score,
        "models": ["TF-IDF + Logistic Regression (scikit-learn)", "Rule engine (URL / header / cue analysis)",
                   "Stylometric AI-text estimator"],
        "details": {"subject": subject, "urls_found": len(urls), "words": len(re.findall(r"\w+", body)),
                    "attachments": headers.get("_attachments", "")},
    }
