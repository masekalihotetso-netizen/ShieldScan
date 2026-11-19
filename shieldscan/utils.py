import hashlib
import json
import os
import subprocess
import tempfile


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sniff_kind(path, ext):
    """Decide modality from the file signature first, extension second."""
    with open(path, "rb") as f:
        head = f.read(16)
    if head.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"BM")):
        return "image"
    if head[:4] == b"RIFF":
        tag = head[8:12]
        return {b"WEBP": "image", b"WAVE": "audio", b"AVI ": "video"}.get(tag)
    if head.startswith((b"OggS", b"fLaC", b"ID3")) or head[:2] in (b"\xff\xfb", b"\xff\xf3"):
        return "audio"
    if head.startswith(b"\x1aE\xdf\xa3"):
        return "video"
    if head[4:8] == b"ftyp":
        return "audio" if ext == ".m4a" else "video"
    return None


def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, float(x)))


def ramp(x, lo, hi):
    """Linear 0..1 ramp from lo to hi (works when lo > hi too)."""
    if lo == hi:
        return 0.0
    return clamp((x - lo) / (hi - lo))


def to_wav(src, seconds, sr=16000):
    """Decode any audio/video container to mono 16 kHz WAV (temporary file)."""
    out = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
    out.close()
    cmd = ["ffmpeg", "-nostdin", "-v", "error", "-y", "-i", src, "-vn", "-ac", "1",
           "-ar", str(sr), "-t", str(seconds), out.name]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=180)
    except Exception:
        r = None
    if r is None or r.returncode != 0 or os.path.getsize(out.name) < 1000:
        os.unlink(out.name)
        return None
    return out.name


def ffprobe_meta(path):
    try:
        r = subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format",
                            "-show_streams", path], capture_output=True, timeout=30)
        return json.loads(r.stdout or b"{}")
    except Exception:
        return {}
