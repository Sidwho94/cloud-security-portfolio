"""Sample Microservice Application demonstrating secure coding practices."""
from flask import Flask, jsonify, request
import html
import logging
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secure-app")


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint used by orchestrators."""
    return jsonify({"status": "healthy", "service": "payment-gateway"}), 200


@app.route("/api/v1/echo", methods=["POST"])
def echo_payload():
    """Sanitizes user input to prevent injection attacks."""
    data = request.get_json(silent=True)
    if not data or "message" not in data:
        return jsonify({"error": "Bad Request", "message": "Expected JSON payload with 'message'"}), 400

    raw_message = str(data["message"])
    # HTML sanitize to prevent XSS / script reflection
    safe_message = html.escape(raw_message)
    return jsonify({"safe_echo": safe_message}), 200


if __name__ == "__main__":
    # Bound to non-privileged port, avoiding root requirement
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
