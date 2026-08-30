#!/usr/bin/env python3

import os
import base64
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

GENERIC_ERROR = {"error": "Access denied or file not found"}
CHALLENGE_DIR = "/app"
FORBIDDEN_PREFIXES = ("/etc", "/dev", "/proc", "/entrypoint.sh")

MAX_PATH_LEN = 110
MAX_CONTENT_LENGTH = 65536


def is_forbidden(resolved: str) -> bool:
    for prefix in FORBIDDEN_PREFIXES:
        if resolved == prefix or resolved.startswith(prefix + "/"):
            return True
    return False


def resolve(user_path):
    if not isinstance(user_path, str):
        return None
    if not user_path.startswith("/"):
        return None
    if len(user_path) > MAX_PATH_LEN:
        return None
    if "\x00" in user_path or "\\" in user_path:
        return None

    cleaned = user_path.replace("../", "")
    resolved = os.path.normpath(CHALLENGE_DIR + cleaned)

    if is_forbidden(resolved):
        return None
    return resolved


def bad_data(data: bytes) -> bool:
    BLOCKED = (bytes([65, 83, 73, 83]), bytes([108, 105, 98]))
    return any(marker in data for marker in BLOCKED)


@app.route("/", methods=["GET"])
def index():
    try:
        with open(os.path.abspath(__file__), "r") as f:
            app_source = f.read()
    except Exception:
        app_source = "# source unavailable"
    return app_source


@app.route("/inspect", methods=["GET"])
def inspect_file():
    try:
        target = request.args.get("path")
        if not target:
            return jsonify(GENERIC_ERROR), 400

        resolved = resolve(target)
        if resolved is None:
            return jsonify(GENERIC_ERROR), 400

        if not os.path.exists(resolved) or os.path.isdir(resolved):
            return jsonify(GENERIC_ERROR), 400

        response = send_file(resolved, conditional=True)
        response.direct_passthrough = False
        body = response.get_data()

        if bad_data(body):
            return jsonify(GENERIC_ERROR), 400

        if len(body) > MAX_CONTENT_LENGTH:
            return jsonify(GENERIC_ERROR), 400

        return jsonify({
            "content": base64.b64encode(body).decode("ascii")
        }), 200

    except Exception:
        return jsonify(GENERIC_ERROR), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

