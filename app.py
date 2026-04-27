from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from functools import wraps
import sqlite3
import jwt
import datetime
import logging

app = Flask(__name__)
bcrypt = Bcrypt(app)

SECRET_KEY = "secure_shield_secret_key"
BLACKLISTED_TOKENS = set()

# -----------------------------
# Security Logging Setup
# -----------------------------
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# -----------------------------
# Database Setup
# -----------------------------
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# -----------------------------
# Helper Function
# -----------------------------
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------
# Task 1: Register User
# -----------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password are required"}), 400

    username = data["username"]
    password = data["password"]
    role = data.get("role", "User")

    if role not in ["User", "Admin"]:
        return jsonify({"error": "Role must be either User or Admin"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_password, role)
        )
        conn.commit()
        return jsonify({"message": "User registered successfully"}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    finally:
        conn.close()


# -----------------------------
# Task 2: Login and JWT Issuance
# -----------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password are required"}), 400

    username = data["username"]
    password = data["password"]

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if user and bcrypt.check_password_hash(user["password"], password):
        token = jwt.encode(
            {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            },
            SECRET_KEY,
            algorithm="HS256"
        )

        return jsonify({
            "message": "Login successful",
            "token": token
        }), 200

    return jsonify({"error": "Invalid username or password"}), 401


# -----------------------------
# Task 3: Token Validation
# -----------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"error": "Token is missing"}), 401

        try:
            token = auth_header.split(" ")[1]
        except IndexError:
            return jsonify({"error": "Invalid token format. Use Bearer <token>"}), 401

        if token in BLACKLISTED_TOKENS:
            return jsonify({"error": "Token has been revoked. Please login again"}), 401

        try:
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = decoded_token
            request.token = token

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401

        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated


# -----------------------------
# Admin Role Required Decorator
# -----------------------------
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.user.get("role") != "Admin":
            attempted_action = request.path
            username = request.user.get("username", "Unknown")

            logging.warning(
                f"Unauthorized access attempt by user '{username}' "
                f"to admin route '{attempted_action}'"
            )

            return jsonify({
                "error": "403 Forbidden: Admin access required"
            }), 403

        return f(*args, **kwargs)

    return decorated


# -----------------------------
# Task 4: Profile Route
# User and Admin can access
# -----------------------------
@app.route("/profile", methods=["GET"])
@token_required
def profile():
    return jsonify({
        "message": "Profile access granted",
        "user": {
            "id": request.user["id"],
            "username": request.user["username"],
            "role": request.user["role"]
        }
    }), 200


# -----------------------------
# Task 4: Admin-only Delete User
# -----------------------------
@app.route("/user/<int:user_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    return jsonify({
        "message": f"User with ID {user_id} deleted successfully"
    }), 200


# -----------------------------
# Task 5: Logout / Token Blacklist
# -----------------------------
@app.route("/logout", methods=["POST"])
@token_required
def logout():
    BLACKLISTED_TOKENS.add(request.token)

    return jsonify({
        "message": "Logout successful. Token has been revoked"
    }), 200


# -----------------------------
# Home Route
# -----------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "SecureShield API is running"
    }), 200


# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)