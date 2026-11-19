"""Image analysis: metadata, error-level analysis, spectral (GAN-upsampling) check, noise
consistency, QR-code inspection and brand-logo imitation."""
import glob
import io
import os

import cv2
import numpy as np
from PIL import Image, ExifTags

from . import config
from .utils import clamp, ramp

EDIT_TOOLS = ("photoshop", "gimp", "affinity", "canva", "paint.net", "pixlr", "faceapp", "facetune", "snapseed")
GEN_TOOLS = ("stable diffusion", "midjourney", "dall", "firefly", "comfyui", "automatic1111", "novelai", "sdxl",
             "generated", "ai generated")


def _load(path):
    im = Image.open(path)
    im.load()
    return im


def metadata_check(im, ev):
    score = 0.0
    exif = {}
    try:
        raw = im.getexif()
        exif = {ExifTags.TAGS.get(k, k): v for k, v in raw.items()}
    except Exception:
        pass
    info_text = " ".join(str(v) for v in list(im.info.values())[:20] if isinstance(v, (str, bytes))).lower()
    soft = str(exif.get("Software", "")).lower() + " " + info_text
    if any(t in soft for t in GEN_TOOLS):
        ev.append(("high", "Metadata names an AI image generator")); score = 0.95
    elif any(t in soft for t in EDIT_TOOLS):
        ev.append(("medium", "Metadata shows editing software: " + str(exif.get("Software", "")))); score = 0.45
    if im.format == "JPEG" and not any(k in exif for k in ("Make", "Model", "DateTime")):
        ev.append(("info", "No camera make/model/date in metadata (typical of generated or stripped images)"))
        score = max(score, 0.2)
    return score, {"exif_fields": len(exif), "format": im.format}


def ela_check(im, ev):
    """Error-level analysis: edited regions recompress differently from the rest."""
    rgb = im.convert("RGB")
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=90)
    buf.seek(0)
    re_im = Image.open(buf).convert("RGB")
    diff = np.abs(np.asarray(rgb, np.int16) - np.asarray(re_im, np.int16)).sum(axis=2).astype(np.float32)
    h, w = diff.shape
    bs = max(16, min(h, w) // 12)
    blocks = [diff[y:y + bs, x:x + bs].mean() for y in range(0, h - bs, bs) for x in range(0, w - bs, bs)]
    if len(blocks) < 12:
        return 0.0, {}
    b = np.array(blocks)
    med = np.median(b) + 1e-3
    hot = float((b > 3.0 * med + 2).mean())
    spread = float(np.percentile(b, 95) / med)
    cold = float((b < 0.3 * med).mean())          # re-compressed-twice areas (pasted from another JPEG)
    s = max(0.6 * ramp(hot, 0.02, 0.15) + 0.4 * ramp(spread, 2.5, 6.0), ramp(cold, 0.02, 0.08))
    if s > 0.5:
        ev.append(("medium", f"Error-level analysis shows inconsistent compression in {hot*100:.0f}% of blocks (possible splice/edit)"))
    return clamp(s), {"ela_hot_blocks": round(hot, 3), "ela_cold_blocks": round(cold, 3), "ela_spread": round(spread, 2)}


def spectral_check(im, ev):
    """Generated images often carry periodic upsampling peaks in the 2-D spectrum."""
    g = np.asarray(im.convert("L").resize((512, 512)), np.float32)
    g = (g - g.mean()) * np.hanning(512)[:, None] * np.hanning(512)[None, :]
    f = np.log1p(np.abs(np.fft.fftshift(np.fft.fft2(g))))
    yy, xx = np.indices(f.shape)
    r = np.hypot(yy - 256, xx - 256).astype(int)
    radial = np.bincount(r.ravel(), f.ravel()) / np.maximum(np.bincount(r.ravel()), 1)
    prof = radial[20:250]
    resid = f - np.take(radial, r)
    mask = (r > 40) & (r < 250)
    peak = float(resid[mask].max() / (resid[mask].std() + 1e-6))
    hf_ratio = float(prof[-60:].mean() / (prof[:60].mean() + 1e-6))
    s = 0.8 * ramp(peak, 6, 10) + 0.2 * ramp(hf_ratio, 0.5, 0.1)
    if s > 0.5:
        ev.append(("medium", "Frequency spectrum shows periodic peaks / atypical high-frequency roll-off consistent with synthetic upsampling"))
    return clamp(s), {"spectral_peak_ratio": round(peak, 4), "hf_ratio": round(hf_ratio, 3)}


def noise_check(im, ev):
    """Camera sensor noise is spatially consistent; pasted or generated regions break that."""
    g = np.asarray(im.convert("L"), np.float32)
    res = g - cv2.GaussianBlur(g, (0, 0), 1.5)
    h, w = res.shape
    bs = max(32, min(h, w) // 8)
    sig = np.array([res[y:y + bs, x:x + bs].std() for y in range(0, h - bs, bs) for x in range(0, w - bs, bs)])
    if len(sig) < 9:
        return 0.0, {}
    mad = np.median(np.abs(sig - np.median(sig))) + 0.15
    outl = float((np.abs(sig - np.median(sig)) > 5 * mad).mean())
    cv_ = float(sig.std() / (sig.mean() + 1e-3))
    too_clean = float(np.median(sig))
    s = max(0.7 * ramp(cv_, 0.6, 1.4) + 0.3 * ramp(too_clean, 1.2, 0.5), ramp(outl, 0.03, 0.10))
    if s > 0.5:
        ev.append(("medium", "Noise pattern is inconsistent across the image or unnaturally smooth"))
    return clamp(s), {"noise_cv": round(cv_, 2), "noise_outlier_blocks": round(outl, 3), "noise_median": round(too_clean, 2)}


def qr_check(path, ev):
    try:
        img = cv2.imread(path)
        if img is None:
            return 0.0, {}
        data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
        if data:
            from .text_detector import analyse_urls
            _, f, sc = analyse_urls(data, "")
            ev.append(("medium", f"QR code found, destination: {data[:90]}"))
            for sev, m in f:
                ev.append((sev, "QR code: " + m))
            return max(0.3, sc), {"qr_url": data[:200]}
    except Exception:
        pass
    return 0.0, {}


_logo_cache = None


def _logos():
    global _logo_cache
    if _logo_cache is None:
        orb = cv2.ORB_create(500)
        _logo_cache = []
        for p in glob.glob(os.path.join(config.LOGO_DIR, "*.*")):
            im = cv2.imread(p, cv2.IMREAD_GRAYSCALE)
            if im is None:
                continue
            kp, des = orb.detectAndCompute(im, None)
            if des is not None and len(kp) >= 12:
                _logo_cache.append((os.path.splitext(os.path.basename(p))[0], des))
    return _logo_cache


def logo_check(path, ev):
    """Detect reused brand logos (ORB feature matching against ./logos). Combined with
    other indicators it highlights brand impersonation."""
    logos = _logos()
    if not logos:
        return 0.0, {"logos_registered": 0}
    img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return 0.0, {}
    orb = cv2.ORB_create(1500)
    kp, des = orb.detectAndCompute(img, None)
    if des is None:
        return 0.0, {}
    bf = cv2.BFMatcher(cv2.NORM_HAMMING)
    best, name = 0, None
    for n, d in logos:
        good = [m for m, k in (p for p in bf.knnMatch(d, des, k=2) if len(p) == 2) if m.distance < 0.7 * k.distance]
        if len(good) > best:
            best, name = len(good), n
    if best >= 12:
        ev.append(("medium", f"Image reuses the '{name}' brand logo ({best} feature matches) - verify the sender really is that brand"))
        return 0.45, {"logo": name, "matches": best}
    return 0.0, {"logos_registered": len(logos)}


def analyse(path):
    ev, steps = [], []
    im = _load(path)
    w, h = im.size
    if max(w, h) > config.IMAGE_MAX_SIDE:
        s = config.IMAGE_MAX_SIDE / max(w, h)
        small = im.resize((int(w * s), int(h * s)))
    else:
        small = im
    det = {"width": w, "height": h}
    m, d = metadata_check(im, ev); det.update(d)
    steps.append("Metadata / EXIF inspection")
    e, d = ela_check(small, ev); det.update(d)
    steps.append("Error-level analysis (splicing / editing)")
    sp, d = spectral_check(small, ev); det.update(d)
    steps.append("Frequency-domain analysis (GAN / diffusion artefacts)")
    n, d = noise_check(small, ev); det.update(d)
    steps.append("Sensor-noise consistency check")
    q, d = qr_check(path, ev); det.update(d)
    steps.append("QR-code decoding and URL analysis")
    lg, d = logo_check(path, ev); det.update(d)
    steps.append("Brand-logo reuse detection (ORB feature matching)")
    forensic = 0.30 * e + 0.30 * sp + 0.25 * n + 0.15 * m
    single = 0.65 * max(e, sp, n)        # one strong indicator alone caps at Medium
    risk = max(forensic * 1.15, single, m if m > 0.9 else 0, q, lg)
    return {"risk": clamp(risk), "evidence": ev, "steps": steps, "details": det,
            "models": ["Error-level analysis", "FFT spectral classifier (rule-based)", "Noise-residual consistency model",
                       "ORB logo matcher", "QR decoder"]}
