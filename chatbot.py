#!/usr/bin/env python3
"""
Combined Flask (Groq-backed) + PyQt6 Chatbot (single-file)

- Starts a Flask/Groq server in a background thread (endpoints: /chat, /conversations, /reset, /health)
- Launches a PyQt6 GUI client that displays conversation history and lets the user send messages
- GUI fetches saved conversations on startup and posts to /chat
- Requirements:
    pip install flask python-dotenv requests pyqt6
- Create a .env file with GROQ_API_KEY (starts with gsk_...) and optionally GROQ_API_URL, DEFAULT_MODEL
- Run: python contextual_chat_with_gui.py
"""

from __future__ import annotations

import os
import time
import json
import logging
import threading
from typing import List, Dict, Any
from pathlib import Path
from time import sleep

import requests
from flask import Flask, request, jsonify, make_response
from dotenv import load_dotenv

# PyQt6
from PyQt6 import QtCore
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton,
    QVBoxLayout, QWidget, QLabel, QHBoxLayout
)
from PyQt6.QtCore import QObject, pyqtSignal, QTimer

# ---------------------- Config & Logging ----------------------
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "llama3-70b-8192")

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "30"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_BACKOFF = float(os.getenv("RETRY_BACKOFF", "0.8"))

logger = logging.getLogger("combined_chatbot")
logger.setLevel(logging.DEBUG if os.getenv("DEBUG", "0") in ("1", "true", "True") else logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
logger.addHandler(handler)

# ---------------------- Flask (server + Groq) ----------------------
app = Flask(__name__)

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = os.getenv("CORS_ALLOW_ORIGIN", "*")
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp

# In-memory conversation store (shared between Flask and GUI)

# Absolute path to file chatbot.py
BASE_DIR = Path(__file__).resolve().parent

# conversations.json in the same
CONV_PATH = BASE_DIR / "conversations.json"
messages: List[Dict[str, Any]] = []

# Load saved conversation from JSON if available
if CONV_PATH.exists():
    try:
        with open(CONV_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            loaded_msgs = data.get("messages", [])
            if isinstance(loaded_msgs, list):
                messages.extend(loaded_msgs)
                logger.info(f"Loaded {len(loaded_msgs)} previous messages from {CONV_PATH}")
    except Exception as e:
        logger.warning(f"Failed to load conversation history: {e}")


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def append_message(role: str, content: str) -> None:
    messages.append({"role": role, "content": content, "ts": _now_ts()})
    # persist to file (best-effort)
    try:
        data = {"meta": {"updated_at": _now_ts()}, "messages": messages}
        tmp = CONV_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(CONV_PATH)
    except Exception as e:
        logger.warning("Failed to persist conversations: %s", e)

# initial system prompt
INITIAL_SYSTEM_PROMPT = os.getenv(
    "INITIAL_SYSTEM_PROMPT",
    "You are a helpful, concise assistant."
)
if os.getenv("SKIP_INITIAL_SYSTEM_PROMPT", "0") not in ("1", "true", "True"):
    append_message("system", INITIAL_SYSTEM_PROMPT)

session = requests.Session()

def groq_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY not set in environment (.env missing or variable incorrect)")

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "combined-chatbot/1.0"
    }

    attempt = 0
    last_exc = None
    while attempt < MAX_RETRIES:
        attempt += 1
        try:
            logger.debug("Calling GROQ (attempt %d) model=%s messages=%d", attempt, payload.get("model"), len(payload.get("messages", [])))
            resp = session.post(GROQ_API_URL, headers=headers, json=payload, timeout=HTTP_TIMEOUT)
            logger.debug("GROQ status=%s", resp.status_code)
            try:
                j = resp.json()
            except ValueError:
                j = None

            if resp.status_code == 200:
                if j is None:
                    raise RuntimeError("GROQ returned 200 but body is not JSON")
                return j

            if resp.status_code in (429, 500, 502, 503, 504):
                backoff = (RETRY_BACKOFF ** attempt) * 0.5
                logger.warning("Transient GROQ error status=%d, retrying in %.2fs body=%s", resp.status_code, backoff, (j or resp.text)[:200])
                time.sleep(backoff)
                continue

            msg = None
            if isinstance(j, dict):
                msg = j.get("error", j.get("detail", j.get("message")))
                if isinstance(msg, dict):
                    msg = msg.get("message") or str(msg)
            raise RuntimeError(f"GROQ API error status={resp.status_code} msg={msg or resp.text}")
        except requests.RequestException as ex:
            last_exc = ex
            backoff = (RETRY_BACKOFF ** attempt) * 0.5
            logger.warning("Network error on GROQ request attempt %d: %s. Retrying in %.2fs", attempt, ex, backoff)
            time.sleep(backoff)
    raise RuntimeError(f"Failed to call GROQ API after {MAX_RETRIES} attempts: {last_exc}")

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "messages_count": len(messages)}), 200

@app.route("/conversations", methods=["GET"])
def get_conversations():
    return jsonify({"meta": {"created_at": messages[0]["ts"] if messages else _now_ts(), "updated_at": _now_ts()}, "messages": messages}), 200

@app.route("/reset", methods=["POST"])
def reset():
    global messages
    messages = []
    if os.getenv("SKIP_INITIAL_SYSTEM_PROMPT", "0") not in ("1", "true", "True"):
        append_message("system", INITIAL_SYSTEM_PROMPT)
    logger.info("Conversation reset")
    return jsonify({"status": "ok", "message": "conversation reset"}), 200

@app.route("/chat", methods=["POST", "OPTIONS"])
def chat_endpoint():
    if request.method == "OPTIONS":
        return _cors_ok()

    try:
        payload = request.get_json(force=True)
    except Exception as e:
        logger.exception("Invalid JSON to /chat")
        return jsonify({"error": "invalid json", "details": str(e)}), 400

    if not payload or "message" not in payload:
        return jsonify({"error": "missing 'message' in request body"}), 400

    user_text = str(payload["message"]).strip()
    if not user_text:
        return jsonify({"error": "empty 'message'"}), 400

    append_message("user", user_text)
    logger.info("User message appended; total messages=%d", len(messages))

    model = payload.get("model", DEFAULT_MODEL)
    max_tokens = int(payload.get("max_tokens", 512))
    temperature = float(payload.get("temperature", 0.7))

    request_body = {
        "model": model,
        "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
        "max_tokens": max_tokens,
        "temperature": temperature
    }

    allowed_extra = ("top_p", "n", "presence_penalty", "frequency_penalty")
    for k in allowed_extra:
        if k in payload:
            request_body[k] = payload[k]

    try:
        groq_resp = groq_request(request_body)
    except Exception as e:
        logger.exception("GROQ call failed: %s", e)
        err_msg = f"(GROQ API error) {e}"
        append_message("assistant", err_msg)
        return jsonify({"reply": err_msg, "status": "error", "details": str(e)}), 502

    assistant_text = None
    try:
        choices = groq_resp.get("choices") if isinstance(groq_resp, dict) else None
        if choices and len(choices) > 0:
            first = choices[0]
            if isinstance(first, dict) and "message" in first and isinstance(first["message"], dict):
                assistant_text = first["message"].get("content")
            if assistant_text is None:
                assistant_text = first.get("text") or first.get("message") or None
        if not assistant_text:
            assistant_text = json.dumps(groq_resp)[:2000]
    except Exception as e:
        logger.exception("Failed to parse GROQ response: %s", e)
        assistant_text = "(error parsing model response)"

    assistant_text = (assistant_text or "").strip() or "(model returned empty reply)"
    append_message("assistant", assistant_text)
    logger.info("Assistant appended; total messages=%d", len(messages))
    return jsonify({"reply": assistant_text, "status": "ok"}), 200

def _cors_ok():
    resp = make_response(("", 204))
    resp.headers["Access-Control-Allow-Origin"] = os.getenv("CORS_ALLOW_ORIGIN", "*")
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp

def run_flask(host="127.0.0.1", port=5000):
    logger.info("Starting Flask server on %s:%d (model=%s)", host, port, DEFAULT_MODEL)
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set — /chat will fail until provided.")
    # Run Flask without reloader in a background thread
    app.run(host=host, port=port, debug=False, use_reloader=False)

# ---------------------- PyQt6 GUI client ----------------------
class Communicator(QObject):
    new_message = pyqtSignal(str, str)  # role, content
    status = pyqtSignal(str)

class ChatWindow(QMainWindow):
    def __init__(self, api_base="http://127.0.0.1:5000"):
        super().__init__()
        self.setWindowTitle("Contextual Chatbot (Groq) — PyQt6 Client")
        self.setWindowIcon("gui/chatbot_icon")
        self.resize(700, 520)

        self.api_base = api_base
        self.comm = Communicator()
        self.comm.new_message.connect(self._on_new_message)
        self.comm.status.connect(self._on_status)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        h = QHBoxLayout()
        self.input_line = QLineEdit()
        self.input_line.returnPressed.connect(self.on_send_clicked)
        h.addWidget(self.input_line)

        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.on_send_clicked)
        h.addWidget(self.send_btn)

        self.clear_btn = QPushButton("Clear History")
        self.clear_btn.clicked.connect(self.on_clear_clicked)
        h.addWidget(self.clear_btn)

        layout.addLayout(h)

        self.status_label = QLabel("Status: ready")
        layout.addWidget(self.status_label)

        self.session = requests.Session()

        # load history on startup in background
        threading.Thread(target=self.load_history, daemon=True).start()

    def _on_status(self, text: str):
        self.status_label.setText(f"Status: {text}")

    def _on_new_message(self, role: str, content: str):
        # Basic rendering; do not render untrusted HTML in production
        if role == "user":
            self.chat_display.append(f"<b>You:</b> {content}")
        elif role == "assistant":
            self.chat_display.append(f"<b>Assistant:</b> {content}")
        else:
            self.chat_display.append(f"<i>{role}:</i> {content}")

    def load_history(self):
        try:
            self.comm.status.emit("loading history...")
            resp = self.session.get(f"{self.api_base}/conversations", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                for m in data.get("messages", []):
                    role = m.get("role", "user")
                    content = m.get("content", "")
                    # emit signals to append in UI thread
                    self.comm.new_message.emit(role, content)
                self.comm.status.emit("history loaded")
            else:
                self.comm.status.emit(f"failed to load ({resp.status_code})")
        except Exception as e:
            self.comm.status.emit(f"error: {e}")

    def on_send_clicked(self):
        text = self.input_line.text().strip()
        if not text:
            return
        self.comm.new_message.emit("user", text)
        self.input_line.clear()
        self.send_btn.setEnabled(False)
        self.comm.status.emit("sending...")
        threading.Thread(target=self.send_message, args=(text,), daemon=True).start()

    def send_message(self, text: str):
        try:
            payload = {"message": text, "model": DEFAULT_MODEL, "load_history": True}
            resp = self.session.post(f"{self.api_base}/chat", json=payload, timeout=60)
            if resp.status_code == 200:
                data = resp.json()
                reply = data.get("reply", "(no reply)")
                self.comm.new_message.emit("assistant", reply)
                self.comm.status.emit("response received")
            else:
                # show server body if available
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
                self.comm.new_message.emit("assistant", f"(server error {resp.status_code}) {body}")
                self.comm.status.emit("server error")
        except Exception as e:
            self.comm.new_message.emit("assistant", f"(network error) {e}")
            self.comm.status.emit("network error")
        finally:
            QTimer.singleShot(0, lambda: self.send_btn.setEnabled(True))

    def on_clear_clicked(self):
        def do_clear():
            try:
                self.comm.status.emit("clearing history...")
                resp = self.session.post(f"{self.api_base}/reset", timeout=5)
                if resp.status_code == 200:
                    QTimer.singleShot(0, lambda: self.chat_display.clear())
                    self.comm.status.emit("history cleared")
                else:
                    self.comm.status.emit(f"clear failed ({resp.status_code})")
            except Exception as e:
                self.comm.status.emit(f"clear error: {e}")
        threading.Thread(target=do_clear, daemon=True).start()

# ---------------------- Main: start server thread + GUI ----------------------
def main():
    # Start Flask server in background thread
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    server_thread = threading.Thread(target=run_flask, args=(host, port), daemon=True)
    server_thread.start()

    # small delay to let server bind
    sleep(0.5)

    # Launch PyQt6 GUI app
    app_qt = QApplication([])
    win = ChatWindow(api_base=f"http://{host}:{port}")
    win.show()
    # On exit, Flask thread will be daemon and exit with process
    app_qt.exec()

if __name__ == "__main__":
    main()