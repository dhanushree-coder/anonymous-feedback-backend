from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import mysql.connector
import os

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

# ================= CONFIG =================
app.config['SECRET_KEY'] = 'super-secret-key'

# ================= BASE URL =================
# Local → http://127.0.0.1:5000
# Railway → https://<your-backend>.up.railway.app
BASE_URL = "https://your-backend-name.up.railway.app"

# ================= MAIL CONFIG =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'feedbacksystembiascontrol@gmail.com'
app.config['MAIL_PASSWORD'] = 'qyyx rvhh kfgv puyv'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ================= DATABASE =================
def get_db_connection():
    return mysql.connector.connect(
        host="yamanote.proxy.rlwy.net",
        user="root",
        password="rPwaOSqIAnqPGlZaArBxSCwURjqaDQFt",
        database="railway",
        port=17639
    )

# ================= SIGNUP =================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json

    name = data["name"]
    email = data["email"]
    username = data["username"]
    password = data["password"]

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    token = serializer.dumps(email, salt="email-confirm")

    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute("""
            INSERT INTO admins (name, email, username, password_hash, is_verified)
            VALUES (%s, %s, %s, %s, 0)
        """, (name, email, username, hashed_password))
        db.commit()
    except mysql.connector.Error:
        return jsonify({"error": "Email or Username already exists"}), 400
    finally:
        cursor.close()
        db.close()

    verify_link = f"{BASE_URL}/verify/{token}"

    msg = Message(
        "Verify Your Admin Account",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    msg.body = f"Click the link below to verify your account:\n\n{verify_link}"
    mail.send(msg)

    return jsonify({"message": "Verification email sent"}), 200

# ================= EMAIL VERIFY =================
@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = serializer.loads(token, salt="email-confirm", max_age=3600)
    except:
        return "Verification link expired", 400

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE admins SET is_verified=1 WHERE email=%s", (email,))
    db.commit()
    cursor.close()
    db.close()

    return redirect(f"{BASE_URL}/email-verified.html")

# ================= LOGIN =================
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admins WHERE username=%s", (username,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not user["is_verified"]:
        return jsonify({"error": "Please verify your email first"}), 403

    if not bcrypt.check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful"}), 200

if __name__ == "__main__":
    app.run(debug=True)
