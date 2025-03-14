from flask import Flask, request, jsonify, render_template_string
import jwt
import os
import time

app = Flask(__name__)

# 🔐 Secure Configurations
SECRET_KEY = os.urandom(32)  # 32-byte key for AES-256
TOKEN_SECRET = "my_secure_token"  # Secret for JWT authentication
AUTH_TOKENS = {}  # Stores valid auth tokens

# 🕵️ Fake 404 Page
FAKE_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: black; color: lime; }
        h1 { font-size: 50px; }
        p { font-size: 20px; }
    </style>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found on this server.</p>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def fake_home():
    return render_template_string(FAKE_PAGE)  # Displays fake error page

@app.route("/auth", methods=["POST"])
def generate_auth_token():
    """Issues a secure authentication token."""
    data = request.json
    client_id = data.get("client_id")

    if not client_id:
        return jsonify({"error": "Missing client ID"}), 400

    # 🎟️ Generate JWT Token
    token = jwt.encode({"client_id": client_id, "exp": time.time() + 600}, TOKEN_SECRET, algorithm="HS256")
    AUTH_TOKENS[client_id] = token
    return jsonify({"token": token})

@app.route("/hidden/<token>", methods=["GET"])
def get_encryption_key(token):
    """Returns the key only if a valid auth token is provided."""
    try:
        payload = jwt.decode(token, TOKEN_SECRET, algorithms=["HS256"])
        client_id = payload["client_id"]

        if AUTH_TOKENS.get(client_id) != token:
            return jsonify({"response": generate_random_gibberish()}), 401

        return jsonify({"key": SECRET_KEY.hex()})  # Returns the key in a secure format

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 403

def generate_random_gibberish():
    """Generates random text to mislead unauthorized users."""
    return os.urandom(16).hex()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
