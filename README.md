# ShieldScan - AI-generated phishing email and deepfake media detector

Information Systems Risk Management - Part II. Detects AI-generated phishing and deepfake media in
**text/email, image, audio and video** before the recipient opens them, and includes an
**end-to-end encrypted chat** that scans everything it receives.

## Run
Requirements: Python 3.10+, ffmpeg and ffprobe on PATH.
```
pip install -r requirements.txt
python app.py            # opens http://127.0.0.1:5000
```
Windows: double-click `run.bat`. Standalone `.exe`: run `build_exe.bat` on Windows (PyInstaller).

## Use
* **Scanner tab** - drop a file or paste an email. You get a 0-100 risk score, evidence, advice, models used, checks
  performed, timing and a SHA-256 integrity proof. Reports download as JSON.
* **Inbox tab (new)** - connect to your real mailbox over IMAP/SSL. ShieldScan fetches your newest 10-25 messages
  **read-only** (nothing is marked read, moved or deleted), scans each message *and every attachment* (photos, voice notes,
  video, files) and gives a verdict: **Genuine** (sender verified by SPF/DKIM/DMARC and no red flags), **Unverified**,
  **Suspicious**, or **Fake / malicious**. Passwords are used once, kept in memory only, never saved or logged.
  Gmail, Yahoo and iCloud need an **App Password** (not your normal password). Microsoft has disabled password sign-in
  for many Outlook accounts; for those, export the message as `.eml` and use the Scanner tab.
* **Secure chat tab** - open two windows, join the same room code. Messages/attachments are encrypted in the browser
  (ECDH P-256 + AES-256-GCM); the server sees ciphertext only. Received items are scanned before they can be saved.
  Compare the *safety number* by phone to rule out interception.
* Brand-logo detection: drop reference logos (png/jpg) into `logos/`.

## What was fixed in this version
* Video scans crashed on OpenCV 5 (`CascadeClassifier` removed) - requirements now pin `opencv-python-headless>=4.9,<5`.
* Email headers: the **first** (top-most, added by your own mail server) `Authentication-Results` is trusted; before, a
  forged lower header could override the real result. Duplicate `From` headers are now flagged.
* The saved text model is rebuilt automatically if it was saved with a different scikit-learn version.
* Reports are capped in memory; chat endpoints validate their input.
## Layout
```
app.py                    Flask app (scan API + chat relay)
shieldscan/               mailbox (IMAP + whole-message scan), text_detector, image_detector, audio_detector, video_detector, scanner, train_text
templates/ static/        interface
tests/                    python -m unittest discover -s tests
make_samples.py           generates synthetic demo media into samples/
benchmark.py              measures speed, size scaling, integrity -> benchmark_results.json
```

## Models and honesty
Classical, CPU-only models: TF-IDF + logistic regression (text), error-level / FFT / noise-residual forensics and ORB
logo matching (images), spectral, pitch and noise-floor statistics (audio), face-vs-background and temporal-consistency
analysis (video). The bundled text corpus is a small template-based seed set and the media thresholds were tuned on
synthetic samples, so **retrain/validate on real data before trusting accuracy figures**
(`python -m shieldscan.train_text --csv data.csv`; datasets such as FaceForensics++ and ASVspoof for media).
Sender authentication (SPF/DKIM/DMARC) is the strongest evidence of a *genuine* email; content-based "AI-written" detection is weak and is only a small contributor.
Known weakness: splices of similar content and deepfake faces without a detectable frontal face.

## Configuration (environment variables)
`SHIELD_MAX_MB` (default 200), `SHIELD_VIDEO_FRAMES` (24), `SHIELD_AUDIO_SECONDS` (90), `PORT`.
