"""Synthetic / cloned voice indicators from signal statistics (no GPU needed)."""
import os
import wave

import numpy as np
from scipy import signal

from . import config
from .utils import clamp, ramp, to_wav, ffprobe_meta


def _read(path):
    with wave.open(path, "rb") as w:
        sr = w.getframerate()
        n = w.getnframes()
        x = np.frombuffer(w.readframes(n), dtype=np.int16).astype(np.float32) / 32768.0
    return x, sr


def features(x, sr):
    f, t, S = signal.stft(x, sr, nperseg=512, noverlap=256)
    P = np.abs(S) ** 2 + 1e-12
    frame_e = P.sum(axis=0)
    voiced = frame_e > np.percentile(frame_e, 50)
    flat = np.exp(np.mean(np.log(P), axis=0)) / np.mean(P, axis=0)
    # band-limit: energy above 7 kHz relative to total (TTS/vocoders often roll off)
    hf = P[f > 4500].sum(axis=0) / frame_e
    active = frame_e > 1e-6
    hf_peak = float(np.percentile(hf[active], 90)) if active.sum() > 5 else 0.0      # fricatives/breath keep some HF in real speech
    fr = np.array([np.sqrt(np.mean(x[i:i + 512] ** 2)) for i in range(0, len(x) - 512, 256)])
    floor_db = float(20 * np.log10(np.percentile(fr, 10) + 1e-9))
    # noise floor: quietest 10% of frames; natural recordings keep a varying floor
    floor = np.percentile(frame_e, 10) / (np.percentile(frame_e, 90) + 1e-12)
    floor_var = float(np.std(np.log(frame_e[frame_e <= np.percentile(frame_e, 25)] + 1e-12)))
    # pitch (autocorrelation on voiced frames)
    hop = 320
    pitches = []
    for i in range(0, len(x) - 1024, hop * 2):
        seg = x[i:i + 1024]
        if np.sqrt(np.mean(seg ** 2)) < 0.01:
            continue
        ac = np.correlate(seg, seg, "full")[1023:]
        lo, hi = int(sr / 400), int(sr / 70)
        k = np.argmax(ac[lo:hi]) + lo
        if ac[k] > 0.35 * ac[0]:
            pitches.append(sr / k)
    pitch_cv = float(np.std(pitches) / np.mean(pitches)) if len(pitches) > 20 else None
    # spectral-flux regularity: synthetic speech often has smoother frame-to-frame change
    mag = np.sqrt(P)
    flux = np.sqrt(np.sum(np.diff(mag, axis=1) ** 2, axis=0))
    flux_cv = float(np.std(flux) / (np.mean(flux) + 1e-9))
    return {"hf_ratio": hf_peak, "floor_db": floor_db, "floor": float(floor), "floor_var": floor_var,
            "pitch_cv": pitch_cv, "flux_cv": flux_cv, "flat": float(np.median(flat[voiced])),
            "pitch_frames": len(pitches)}


def analyse(path, from_video=False):
    ev, steps = [], []
    wav = to_wav(path, config.AUDIO_MAX_SECONDS)
    if wav is None:
        return {"risk": 0.0, "evidence": [("info", "No decodable audio track found")], "steps": [], "details": {}, "models": []}
    try:
        x, sr = _read(wav)
    finally:
        os.unlink(wav)
    dur = len(x) / sr
    det = {"duration_s": round(dur, 1)}
    if dur < 1.5 or np.abs(x).max() < 1e-3:
        return {"risk": 0.0, "evidence": [("info", "Audio too short or silent to analyse reliably")], "steps": [], "details": det, "models": []}
    ft = features(x, sr)
    det.update({k: (round(v, 3) if isinstance(v, float) else v) for k, v in ft.items()})
    steps += ["Decoding to 16 kHz mono (ffmpeg)", "Spectral / band-limit analysis", "Noise-floor analysis",
              "Pitch-variation analysis", "Spectral-flux regularity"]
    s_hf = ramp(ft["hf_ratio"], 0.004, 0.0002)
    s_floor = ramp(ft["floor_db"], -62, -85)          # near-digital silence between words
    s_floor2 = 0.0
    s_pitch = ramp(ft["pitch_cv"], 0.20, 0.04) if ft["pitch_cv"] is not None else 0.0
    s_flux = ramp(ft["flux_cv"], 1.2, 0.6)
    if s_hf > .6: ev.append(("medium", "Hard high-frequency cut-off typical of neural vocoders / TTS"))
    if s_floor > .6 or s_floor2 > .6: ev.append(("medium", "Unnaturally clean background between words (no room noise)"))
    if s_pitch > .6: ev.append(("medium", "Pitch contour is unusually flat or regular"))
    if s_flux > .6: ev.append(("medium", "Frame-to-frame spectral change is unusually uniform"))
    risk = 0.25 * s_hf + 0.25 * max(s_floor, s_floor2) + 0.30 * s_pitch + 0.20 * s_flux
    meta = ffprobe_meta(path)
    enc = (meta.get("format", {}).get("tags", {}) or {})
    tool = " ".join(str(v) for v in enc.values()).lower()
    if any(t in tool for t in ("elevenlabs", "tts", "synthes", "polly", "wavenet", "coqui", "bark")):
        ev.append(("high", "Metadata names a speech-synthesis tool")); risk = max(risk, 0.9)
    steps.append("Container metadata inspection")
    return {"risk": clamp(risk * 1.2), "evidence": ev, "steps": steps, "details": det,
            "models": ["Spectral/band-limit voice-synthesis detector", "Pitch & noise-floor statistical model"]}
