"""Generate synthetic demo/test media into ./samples (no downloads needed).
These are stand-ins for pipeline testing, NOT real deepfakes. Test on real datasets
(e.g. FaceForensics++, ASVspoof, Enron/Nazario phishing corpus) for genuine accuracy."""
import os
import subprocess
import wave

import cv2
import numpy as np
from PIL import Image

OUT = os.path.join(os.path.dirname(__file__), "samples")
os.makedirs(OUT, exist_ok=True)
rng = np.random.default_rng(3)


def scene(w=960, h=640):
    y, x = np.mgrid[0:h, 0:w].astype(np.float32)
    base = 90 + 60 * np.sin(x / 140) * np.cos(y / 110) + 0.08 * x
    img = np.stack([base, base * 0.9 + 20, base * 0.8 + 35], -1)
    for _ in range(14):
        cx, cy, r = rng.integers(0, w), rng.integers(0, h), rng.integers(30, 110)
        c = rng.integers(40, 230, 3)
        m = (x - cx) ** 2 + (y - cy) ** 2 < r * r
        img[m] = 0.6 * img[m] + 0.4 * c
    img = cv2.GaussianBlur(img, (0, 0), 2.2)
    return img


def save_real(name):
    img = scene()
    # texture + sensor noise that scales with brightness, like a camera
    img += rng.normal(0, 1, img.shape) * (2.0 + 0.04 * img)
    im = Image.fromarray(np.clip(img, 0, 255).astype(np.uint8))
    ex = Image.Exif(); ex[271] = "Canon"; ex[272] = "EOS 80D"; ex[306] = "2026:10:02 10:11:12"
    im.save(os.path.join(OUT, name), quality=92, exif=ex)


def save_spliced(name):
    base = np.asarray(Image.open(os.path.join(OUT, "photo_real.jpg")), np.uint8).copy()
    patch = scene(260, 200).astype(np.float32) + rng.normal(0, 6, (200, 260, 3))
    tmp = os.path.join(OUT, "_p.jpg")
    Image.fromarray(np.clip(patch, 0, 255).astype(np.uint8)).save(tmp, quality=55)
    p = np.asarray(Image.open(tmp), np.uint8); os.remove(tmp)
    base[200:400, 300:560] = p
    ex = Image.Exif(); ex[305] = "Adobe Photoshop 25.0"
    Image.fromarray(base).save(os.path.join(OUT, name), quality=92, exif=ex)


def save_generated(name):
    img = scene()
    # ultra-smooth + periodic upsampling pattern (2x nearest-neighbour style grid)
    yy, xx = np.mgrid[0:img.shape[0], 0:img.shape[1]]
    img += (3.5 * np.sin(2 * np.pi * xx / 8) * np.sin(2 * np.pi * yy / 8))[..., None]
    Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).save(os.path.join(OUT, name), "PNG",
        pnginfo=None)


def voice(natural, sr=16000, dur=8):
    t = np.arange(int(sr * dur)) / sr
    if natural:
        f0 = 120 + 25 * np.sin(2 * np.pi * 0.35 * t) + 12 * np.sin(2 * np.pi * 1.7 * t) + rng.normal(0, 1.5, t.size).cumsum() * 0.02
        gate = (np.sin(2 * np.pi * 0.9 * t + 1) > -0.2).astype(float)
        gate = np.convolve(gate, np.ones(800) / 800, "same")
        noise = rng.normal(0, 0.004, t.size)
        from scipy import signal as _sg
        b, a = _sg.butter(4, 3500 / 8000, "high")
        burst = (np.sin(2 * np.pi * 0.9 * t + 1) < -0.5).astype(float)
        noise = noise + _sg.lfilter(b, a, rng.normal(0, 0.05, t.size)) * np.convolve(burst, np.ones(400) / 400, "same")
    else:
        f0 = 140 + 1.5 * np.sin(2 * np.pi * 0.2 * t)
        gate = (np.sin(2 * np.pi * 0.9 * t + 1) > -0.2).astype(float)
        noise = 0 * t
    phase = 2 * np.pi * np.cumsum(f0) / sr
    sig = sum((1 / k) * np.sin(k * phase) for k in range(1, 28 if natural else 12))
    sig = sig * gate * (0.2 + (0.05 * np.sin(2 * np.pi * 3.1 * t) if natural else 0))
    sig = sig + noise
    if not natural:
        from scipy import signal
        b, a = signal.butter(8, 3800 / (sr / 2)); sig = signal.lfilter(b, a, sig)
    return (np.clip(sig, -1, 1) * 32767).astype(np.int16), sr


def save_wav(name, natural):
    x, sr = voice(natural)
    with wave.open(os.path.join(OUT, name), "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr); w.writeframes(x.tobytes())


def save_video(name, secs=6, w=640, h=360, fps=24):
    p = os.path.join(OUT, "_v.avi")
    vw = cv2.VideoWriter(p, cv2.VideoWriter_fourcc(*"MJPG"), fps, (w, h))
    base = scene(w, h).astype(np.uint8)
    for i in range(secs * fps):
        M = np.float32([[1, 0, (i % 40) - 20], [0, 1, 0]])
        fr = cv2.warpAffine(base, M, (w, h), borderMode=cv2.BORDER_REFLECT)
        fr = np.clip(fr + rng.normal(0, 3, fr.shape), 0, 255).astype(np.uint8)
        vw.write(fr)
    vw.release()
    save_wav("_a.wav", True)
    subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-y", "-i", p, "-i", os.path.join(OUT, "_a.wav"),
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", os.path.join(OUT, name)], check=True)
    os.remove(p); os.remove(os.path.join(OUT, "_a.wav"))


PHISH = b"""From: "Dr. Mokoena (CEO)" <ceo.mokoena@gmail.com>
Reply-To: payments@secure-mail.xyz
Subject: Urgent confidential payment
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Dear Thabo, I hope this message finds you well. I am in a closed-door board meeting and cannot take calls.
I need you to urgently process a confidential payment of M85000 to a new supplier today.
Please keep this between us and confirm once done. Update the banking details at
http://standardbank-secure-login.xyz/verify before you pay. Regards, CEO
"""
LEGIT = b"""From: Lerato Phiri <lerato.phiri@luct.example.edu>
To: Thabo <thabo@luct.example.edu>
Subject: Minutes from Tuesday
Authentication-Results: mx.luct.example.edu; spf=pass; dkim=pass; dmarc=pass

Hi Thabo, attached are the minutes from Tuesday's meeting. The next steps are at the bottom.
Let me know if I missed anything and we can go through it at Thursday's catch-up. Thanks, Lerato
"""

if __name__ == "__main__":
    open(os.path.join(OUT, "phishing_ceo_fraud.eml"), "wb").write(PHISH)
    open(os.path.join(OUT, "legit_minutes.eml"), "wb").write(LEGIT)
    save_real("photo_real.jpg"); save_spliced("photo_spliced.jpg"); save_generated("image_synthetic.png")
    save_wav("voice_natural.wav", True); save_wav("voice_synthetic.wav", False)
    save_video("clip_sample.mp4")
    print("samples written to", OUT)
