"""Measure scan time, file-size scaling and file integrity.  Usage: python benchmark.py
Writes benchmark_results.json and prints a table. Test files are generated locally."""
import json
import os
import subprocess
import tempfile
import time
import wave

import cv2
import numpy as np
from PIL import Image

from shieldscan.scanner import scan_file
import make_samples as ms

rng = np.random.default_rng(1)
tmp = tempfile.mkdtemp(prefix="bench_")
rows = []


def run(kind, label, path, runs=2):
    ts = []
    for _ in range(runs):
        r = scan_file(path, os.path.basename(path)); ts.append(r["elapsed_s"])
    rows.append({"kind": kind, "case": label, "size_mb": round(os.path.getsize(path) / 1048576, 2),
                 "avg_s": round(sum(ts) / len(ts), 2), "score": r["score"], "intact": r["integrity"]["unchanged"]})
    print(f'{kind:6s}{label:22s}{rows[-1]["size_mb"]:9.2f} MB {rows[-1]["avg_s"]:7.2f} s  intact={r["integrity"]["unchanged"]}')


# text / email
base = ms.PHISH.decode()
for mb in (0.01, 1, 10, 50):
    p = os.path.join(tmp, f"mail_{mb}.eml"); body = (base.split("\n\n", 1)[1] + "\n") * int(mb * 1048576 / 330 + 1)
    open(p, "w").write(base.split("\n\n", 1)[0] + "\n\n" + body); run("text", f"{mb} MB email", p)
# images
for mp in (0.5, 2, 8, 24):
    w = int((mp * 1e6 * 1.5) ** .5); h = int(w / 1.5)
    img = ms.scene(min(w, 1200), min(h, 800)).astype(np.float32)
    img = cv2.resize(img, (w, h)) + rng.normal(0, 3, (h, w, 3))
    p = os.path.join(tmp, f"img_{mp}mp.jpg"); Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).save(p, quality=92)
    run("image", f"{mp} megapixel JPEG", p)
# audio
for sec in (10, 60, 300, 1800):
    x, sr = ms.voice(True, dur=min(sec, 60)); x = np.tile(x, int(np.ceil(sec / 60)))[: sr * sec]
    p = os.path.join(tmp, f"aud_{sec}s.wav")
    with wave.open(p, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr); w.writeframes(x.tobytes())
    run("audio", f"{sec} s WAV", p, runs=1 if sec > 60 else 2)
# video
for sec, res in ((10, "1280x720"), (30, "1280x720"), (60, "1280x720"), (30, "1920x1080")):
    p = os.path.join(tmp, f"vid_{sec}s_{res}.mp4")
    subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-y", "-f", "lavfi", "-i", f"testsrc2=s={res}:r=25:d={sec}",
                    "-f", "lavfi", "-i", f"sine=f=220:d={sec}", "-c:v", "libx264", "-preset", "ultrafast", "-b:v", "6M",
                    "-c:a", "aac", "-shortest", p], check=True)
    run("video", f"{sec} s {res}", p, runs=1)
json.dump(rows, open("benchmark_results.json", "w"), indent=1)
print("\nAverage per type:")
for k in ("text", "image", "audio", "video"):
    v = [r["avg_s"] for r in rows if r["kind"] == k]
    print(f"  {k:6s} {sum(v)/len(v):.2f} s   (all intact: {all(r['intact'] for r in rows if r['kind']==k)})")
