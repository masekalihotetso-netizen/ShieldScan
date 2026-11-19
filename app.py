import base64
import binascii
import copy
import logging
import os
import re
import tempfile
import threading
from collections import OrderedDict

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from shieldscan import __version__, config, mailbox, scanner


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES

MAX_REPORTS = 100
MAX_CHAT_ROOMS = 100
MAX_CHAT_MESSAGES = 200
MAX_CHAT_CIPHERTEXT = 40 * 1024 * 1024

_lock = threading.RLock()
_reports = OrderedDict()
_rooms = {}


def keep(report):
    with _lock:
        _reports[report["id"]] = copy.deepcopy(report)
        _reports.move_to_end(report["id"])
        while len(_reports) > MAX_REPORTS:
            _reports.popitem(last=False)


def _error(message, status):
    return jsonify(error=message), status


def _json_body():
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _room_code(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        return None
    return value


def _chat_name(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 24 or any(ord(char) < 32 for char in value):
        return None
    return value


def _public_key(value):
    if not isinstance(value, dict) or value.get("kty") != "EC" or value.get("crv") != "P-256":
        return None
    x, y = value.get("x"), value.get("y")
    if not all(isinstance(coord, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", coord) for coord in (x, y)):
        return None
    return {"kty": "EC", "crv": "P-256", "x": x, "y": y}


@app.get("/")
def index():
    return render_template("index.html", version=__version__, max_mb=config.MAX_UPLOAD_BYTES // (1024 * 1024))


@app.post("/api/scan")
def scan():
    uploaded = request.files.get("file")
    text = request.form.get("text", "")
    if uploaded and text.strip():
        return _error("Send either a file or pasted text, not both.", 400)

    filename = None
    try:
        with tempfile.TemporaryDirectory(prefix="shieldscan_") as work:
            if uploaded:
                filename = secure_filename(uploaded.filename or "")
                if not filename:
                    return _error("Choose a file with a valid filename.", 400)
                path = os.path.join(work, filename)
                uploaded.save(path)
            elif text.strip():
                filename = "pasted-text.txt"
                path = os.path.join(work, filename)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
            else:
                return _error("Choose a file or enter text to scan.", 400)

            report = scanner.scan_file(path, filename)
    except scanner.UnsupportedFile as exc:
        return _error(str(exc), 400)
    except OSError:
        logging.exception("Could not read the scan input")
        return _error("Could not read the scan input.", 500)
    except Exception as exc:
        logging.exception("Scan failed")
        return _error("Scan failed (" + type(exc).__name__ + ").", 500)

    keep(report)
    return jsonify(report)


@app.get("/api/report/<report_id>")
def get_report(report_id):
    with _lock:
        report = _reports.get(report_id)
        if report is None:
            return _error("Report not found or expired.", 404)
        return jsonify(copy.deepcopy(report))


@app.get("/api/mail/providers")
def mail_providers():
    return jsonify({key: value["label"] for key, value in mailbox.PRESETS.items()})


@app.post("/api/mail/scan")
def mail_scan():
    data = _json_body()
    if data is None:
        return _error("Expected a JSON request.", 400)

    provider = data.get("provider", "custom")
    host = data.get("host", "")
    user = data.get("user", "")
    password = data.get("password", "")
    folder = data.get("folder", "INBOX")
    limit = data.get("limit", 15)

    if not isinstance(provider, str) or provider not in mailbox.PRESETS:
        return _error("Choose a supported mail provider.", 400)
    if not isinstance(host, str) or len(host) > 253:
        return _error("Enter a valid IMAP server name.", 400)
    if not isinstance(user, str) or not user.strip() or len(user) > 320:
        return _error("Enter a valid email address.", 400)
    if not isinstance(password, str) or not password or len(password) > 1024:
        return _error("Enter your app password.", 400)
    if not isinstance(folder, str) or not folder.strip() or len(folder) > 60:
        return _error("Enter a valid mailbox folder.", 400)
    if isinstance(limit, bool):
        return _error("Message limit must be between 1 and 30.", 400)
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return _error("Message limit must be between 1 and 30.", 400)
    if not 1 <= limit <= 30:
        return _error("Message limit must be between 1 and 30.", 400)

    try:
        results = mailbox.scan_mailbox(provider, host, user.strip(), password, folder.strip(), limit)
    except mailbox.MailError as exc:
        return _error(str(exc), 400)
    except Exception as exc:
        logging.exception("Mailbox scan failed")
        return _error("Mailbox scan failed (" + type(exc).__name__ + ").", 500)

    safe_results = []
    for result in results:
        result = copy.deepcopy(result)
        for attachment in result.get("attachments", []):
            attachment.pop("report_id", None)
        keep(result)
        safe_results.append(result)
    return jsonify(messages=safe_results, count=len(safe_results))


@app.post("/api/chat/join")
def chat_join():
    data = _json_body()
    if data is None:
        return _error("Expected a JSON request.", 400)
    room, name = _room_code(data.get("room")), _chat_name(data.get("name"))
    public_key = _public_key(data.get("pub"))
    if room is None or name is None or public_key is None:
        return _error("Provide a valid room code, name, and P-256 public key.", 400)

    with _lock:
        state = _rooms.get(room)
        if state is None:
            if len(_rooms) >= MAX_CHAT_ROOMS:
                return _error("The server is at its room limit. Try again later.", 503)
            state = {"users": {}, "messages": [], "next_id": 1}
            _rooms[room] = state
        current_key = state["users"].get(name)
        if current_key is not None and current_key != public_key:
            return _error("That name is already in use in this room.", 409)
        if current_key is None and len(state["users"]) >= 2:
            return _error("This room already has two participants.", 409)
        state["users"][name] = public_key
        return jsonify(users=copy.deepcopy(state["users"]))


@app.get("/api/chat/poll")
def chat_poll():
    room = _room_code(request.args.get("room"))
    after_value = request.args.get("after", "0")
    if room is None or not re.fullmatch(r"\d{1,16}", after_value):
        return _error("Provide a valid room code and message cursor.", 400)
    after = int(after_value)
    with _lock:
        state = _rooms.get(room)
        if state is None:
            return jsonify(users={}, msgs=[])
        messages = [message for message in state["messages"] if message["id"] > after]
        return jsonify(users=copy.deepcopy(state["users"]), msgs=copy.deepcopy(messages))


@app.post("/api/chat/send")
def chat_send():
    data = _json_body()
    if data is None:
        return _error("Expected a JSON request.", 400)
    room, name = _room_code(data.get("room")), _chat_name(data.get("from"))
    iv, ciphertext = data.get("iv"), data.get("ct")
    if room is None or name is None:
        return _error("Provide a valid room code and participant name.", 400)
    if not isinstance(iv, str) or not isinstance(ciphertext, str) or len(ciphertext) > MAX_CHAT_CIPHERTEXT:
        return _error("Invalid or oversized encrypted message.", 400)
    try:
        iv_bytes = base64.b64decode(iv, validate=True)
        ciphertext_bytes = base64.b64decode(ciphertext, validate=True)
    except (binascii.Error, ValueError):
        return _error("Encrypted message must be base64 encoded.", 400)
    if len(iv_bytes) != 12 or len(ciphertext_bytes) < 16:
        return _error("Invalid encrypted message.", 400)

    with _lock:
        state = _rooms.get(room)
        if state is None or name not in state["users"]:
            return _error("Join the room before sending messages.", 403)
        message = {
            "id": state["next_id"],
            "from": name,
            "iv": iv,
            "ct": ciphertext,
        }
        state["next_id"] += 1
        state["messages"].append(message)
        if len(state["messages"]) > MAX_CHAT_MESSAGES:
            del state["messages"][:-MAX_CHAT_MESSAGES]
        return jsonify(id=message["id"])


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    return _error_response("Request is larger than the configured upload limit.", 413)


def _error_response(message, status):
    return jsonify(error=message), status


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, threaded=True)
