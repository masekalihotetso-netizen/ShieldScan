"""Central configuration. Override with environment variables."""
import os

MAX_UPLOAD_BYTES = int(os.environ.get("SHIELD_MAX_MB", "200")) * 1024 * 1024
VIDEO_MAX_FRAMES = int(os.environ.get("SHIELD_VIDEO_FRAMES", "24"))
AUDIO_MAX_SECONDS = int(os.environ.get("SHIELD_AUDIO_SECONDS", "90"))
IMAGE_MAX_SIDE = 1600          # images are down-scaled for analysis only
LOGO_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logos")

TEXT_EXT = {".txt", ".eml", ".msg", ".html", ".htm"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
AUDIO_EXT = {".wav", ".mp3", ".m4a", ".ogg", ".flac"}
VIDEO_EXT = {".mp4", ".avi", ".mov", ".mkv", ".webm"}

# Verdict thresholds on the 0-100 risk score
LEVELS = [(70, "High"), (40, "Medium"), (0, "Low")]
