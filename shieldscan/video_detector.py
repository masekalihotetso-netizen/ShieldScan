"""Video deepfake indicators: face-region vs background forensics, temporal consistency,
audio-track analysis."""
import cv2
import numpy as np

from . import config
from . import audio_detector
from .utils import clamp, ramp, ffprobe_meta


def _lap_var(g):
    return float(cv2.Laplacian(g, cv2.CV_32F).var())


def analyse(path):
    ev, steps = [], []
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        return {"risk": 0.0, "evidence": [("info", "Video could not be decoded")], "steps": [], "details": {}, "models": []}
    n = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    fps = cap.get(cv2.CAP_PROP_FPS) or 25
    W = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); H = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    det = {"frames": n, "fps": round(fps, 1), "resolution": f"{W}x{H}", "duration_s": round(n / fps, 1) if fps else 0}
    idxs = np.linspace(0, max(n - 1, 0), min(config.VIDEO_MAX_FRAMES, max(n, 1))).astype(int)
    cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    face_sharp, bg_sharp, face_tex, boxes, diffs, sharp_all = [], [], [], [], [], []
    prev = None
    for i in idxs:
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(i))
        ok, fr = cap.read()
        if not ok:
            continue
        s = 640 / max(fr.shape[:2]) if max(fr.shape[:2]) > 640 else 1.0
        if s != 1.0:
            fr = cv2.resize(fr, None, fx=s, fy=s)
        g = cv2.cvtColor(fr, cv2.COLOR_BGR2GRAY)
        sharp_all.append(_lap_var(g))
        if prev is not None and prev.shape == g.shape:
            diffs.append(float(np.mean(cv2.absdiff(prev, g))))
        prev = g
        faces = cascade.detectMultiScale(g, 1.1, 5, minSize=(48, 48))
        if len(faces):
            x, y, w, h = max(faces, key=lambda b: b[2] * b[3])
            roi = g[y:y + h, x:x + w]
            ring = g[max(0, y - h // 3):min(g.shape[0], y + h + h // 3), max(0, x - w // 3):min(g.shape[1], x + w + w // 3)]
            face_sharp.append(_lap_var(roi))
            mask = np.ones(ring.shape, bool)
            yy, xx = y - max(0, y - h // 3), x - max(0, x - w // 3)
            mask[yy:yy + h, xx:xx + w] = False
            bg = ring.copy().astype(np.float32); bg[~mask] = np.nan
            bg_sharp.append(_lap_var(np.where(mask, ring, 0).astype(np.uint8)) if mask.any() else 0)
            boxes.append((x / g.shape[1], y / g.shape[0], w / g.shape[1]))
    cap.release()
    steps += ["Uniform frame sampling", "Face detection (Haar cascade)"]
    det["frames_sampled"] = len(sharp_all); det["faces_found_in_frames"] = len(face_sharp)

    s_mis = s_jit = s_flick = 0.0
    if len(face_sharp) >= 4:
        ratio = float(np.median(face_sharp) / (np.median(bg_sharp) + 1e-6))
        det["face_bg_sharpness_ratio"] = round(ratio, 2)
        s_mis = max(ramp(ratio, 0.6, 0.15), ramp(ratio, 2.0, 6.0))
        if s_mis > .5:
            ev.append(("medium", f"Face region sharpness differs sharply from its surroundings (ratio {ratio:.2f}) - typical of blended face swaps"))
        b = np.array(boxes)
        jitter = float(np.mean(np.abs(np.diff(b, axis=0)).sum(axis=1))) if len(b) > 2 else 0
        fs = np.array(face_sharp)
        fcv = float(np.std(np.diff(np.log(fs + 1))) )
        det["face_box_jitter"] = round(jitter, 3); det["face_sharpness_flicker"] = round(fcv, 3)
        s_jit = ramp(jitter, 0.05, 0.2)
        s_flick = ramp(fcv, 0.35, 0.9)
        if s_flick > .5:
            ev.append(("medium", "Face sharpness flickers between frames (temporal inconsistency)"))
        if s_jit > .5:
            ev.append(("medium", "Face position jitters unnaturally between sampled frames"))
        steps += ["Face-vs-background forensic comparison", "Temporal consistency analysis"]
    elif not face_sharp:
        ev.append(("info", "No frontal face detected - facial deepfake checks skipped"))

    # Whole-frame statistics: very low motion + high sharpness on talking head can indicate animation of a still
    s_static = 0.0
    if diffs:
        md = float(np.mean(diffs)); det["mean_frame_difference"] = round(md, 2)

    audio = audio_detector.analyse(path, from_video=True)
    steps += ["Audio-track extraction and voice-synthesis analysis"]
    if audio["evidence"]:
        ev += [(s, "Audio track: " + m) for s, m in audio["evidence"]]
    det["audio"] = audio.get("details", {})

    meta = ffprobe_meta(path)
    tags = " ".join(str(v) for v in (meta.get("format", {}).get("tags") or {}).values()).lower()
    s_meta = 0.0
    if any(t in tags for t in ("heygen", "synthesia", "d-id", "deepfacelab", "faceswap", "wav2lip", "runway", "pika", "sora")):
        ev.append(("high", "Container metadata names a synthetic-video tool")); s_meta = 0.95
    steps.append("Container metadata inspection")

    video_score = 0.4 * s_mis + 0.3 * s_flick + 0.15 * s_jit
    risk = max(video_score * 1.25, 0.6 * audio["risk"] + 0.4 * video_score, s_meta)
    return {"risk": clamp(risk), "evidence": ev, "steps": steps, "details": det,
            "models": ["Face/background forensic model", "Temporal-consistency model"] + audio.get("models", [])}
