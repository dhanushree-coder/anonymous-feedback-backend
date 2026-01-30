from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import mysql.connector
import os
import json

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SGMail

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

# ================= CONFIG =================
app.config['SECRET_KEY'] = 'super-secret-key'

BASE_URL = "https://web-production-315e.up.railway.app"

# ================= SENDGRID (HTTP API) =================
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
MAIL_SENDER = os.getenv("MAIL_SENDER")

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

# ================= HELPER: send verification email =================
def send_verification_email(email):
    token = serializer.dumps(email, salt="email-confirm")
    verify_link = f"{BASE_URL}/verify/{token}"

    sg_msg = SGMail(
        from_email=MAIL_SENDER,
        to_emails=email,
        subject="Verify Your Admin Account",
        plain_text_content=f"Click the link below to verify your account:\n\n{verify_link}"
    )

    if not SENDGRID_API_KEY or not MAIL_SENDER:
        raise RuntimeError("SENDGRID_API_KEY or MAIL_SENDER not configured")

    sg = SendGridAPIClient(SENDGRID_API_KEY)
    response = sg.send(sg_msg)
    if response.status_code >= 400:
        raise RuntimeError(f"SendGrid error: {response.status_code} {response.body}")

# ================= SIGNUP =================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()

    name = data["name"]
    email = data["email"]
    username = data["username"]
    password = data["password"]

    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute(
        "SELECT id FROM admins WHERE email=%s OR username=%s",
        (email, username)
    )
    if cursor.fetchone():
        cursor.close()
        db.close()
        return jsonify({"error": "Email or Username already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    cursor.execute("""
        INSERT INTO admins (name, email, username, password_hash, is_verified)
        VALUES (%s, %s, %s, %s, 0)
    """, (name, email, username, hashed_password))
    db.commit()

    try:
        send_verification_email(email)
    except Exception as e:
        print("Email send failed:", e)
        cursor.execute("DELETE FROM admins WHERE email=%s", (email,))
        db.commit()
        cursor.close()
        db.close()
        return jsonify({"error": "Email delivery failed"}), 500

    cursor.close()
    db.close()
    return jsonify({"success": True}), 200

# ================= VERIFY =================
@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = serializer.loads(token, salt="email-confirm", max_age=3600)
    except SignatureExpired:
        return "Verification link expired", 400
    except BadSignature:
        return "Invalid verification link", 400
    except Exception:
        return "Verification link error", 400

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE admins SET is_verified=1 WHERE email=%s AND is_verified=0",
        (email,)
    )
    db.commit()
    cursor.close()
    db.close()

    return "Email verified successfully. You can close this tab and login in your app.", 200

# ================= CHECK VERIFICATION STATUS =================
@app.route("/check-verification", methods=["POST"])
def check_verification():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT is_verified FROM admins WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user:
        return jsonify({"exists": False, "is_verified": None}), 200

    return jsonify({"exists": True, "is_verified": user["is_verified"]}), 200

# ================= RESEND VERIFICATION EMAIL =================
@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT is_verified FROM admins WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user:
        return jsonify({"error": "Account not found"}), 404

    if user["is_verified"] == 1:
        return jsonify({"error": "Account already verified"}), 400

    try:
        send_verification_email(email)
    except Exception as e:
        print("Resend email failed:", e)
        return jsonify({"error": "Failed to resend verification email"}), 500

    return jsonify({"success": True}), 200

# ================= LOGIN =================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
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

    if user["is_verified"] != 1:
        return jsonify({"error": "Please verify your email first"}), 403

    if not bcrypt.check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful"}), 200

# ================= FORM TEMPLATE SAVE (CREATE / UPDATE) =================
@app.route("/save-form-template", methods=["POST"])
def save_form_template():
    data = request.get_json()
    domain = data.get("domain")
    status = data.get("status", "draft")
    name = data.get("name", "Untitled Form")
    template_id = data.get("id")  # optional

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    db = get_db_connection()
    cursor = db.cursor()

    json_data = json.dumps(data)

    if template_id:
        # Update existing
        cursor.execute("""
            UPDATE form_templates
            SET name=%s, status=%s, data=%s
            WHERE id=%s
        """, (name, status, json_data, template_id))
    else:
        # Insert new
        cursor.execute("""
            INSERT INTO form_templates (domain, name, status, data)
            VALUES (%s, %s, %s, %s)
        """, (domain, name, status, json_data))
        template_id = cursor.lastrowid

    db.commit()
    cursor.close()
    db.close()

    return jsonify({"success": True, "id": template_id}), 200

# ================= FORM TEMPLATE LOAD (BY ID) =================
@app.route("/load-form-template", methods=["GET"])
def load_form_template():
    template_id = request.args.get("id")
    if not template_id:
        return jsonify({"error": "Template id is required"}), 400

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT data FROM form_templates WHERE id=%s", (template_id,))
    row = cursor.fetchone()
    cursor.close()
    db.close()

    if not row:
        return jsonify({"error": "Template not found"}), 404

    try:
        obj = json.loads(row["data"])
    except Exception:
        obj = {}

    return jsonify(obj), 200

# ================= FORM TEMPLATE LIST (ALL DOMAINS) =================
@app.route("/list-form-templates", methods=["GET"])
def list_form_templates():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, domain, name, status, created_at, updated_at
        FROM form_templates
        ORDER BY updated_at DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    return jsonify(rows), 200

# ================= FORM TEMPLATE DELETE =================
@app.route("/delete-form-template/<int:template_id>", methods=["DELETE"])
def delete_form_template(template_id):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("DELETE FROM form_templates WHERE id=%s", (template_id,))
    db.commit()
    cursor.close()
    db.close()

    return jsonify({"success": True}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
