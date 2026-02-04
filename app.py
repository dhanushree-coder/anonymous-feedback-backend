from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import mysql.connector
import os
import json
import hashlib
from datetime import datetime

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SGMail


app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

# ================= CONFIG =================
app.config['SECRET_KEY'] = 'super-secret-key'

BASE_URL = "https://web-production-315e.up.railway.app"

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
MAIL_SENDER = os.getenv("MAIL_SENDER")

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ---------- RATE LIMITS ----------
FEEDBACK_PER_IP_PER_HOUR = 10
LOGIN_ATTEMPTS_PER_IP_PER_15MIN = 20


# ================= DATABASE =================
def get_db_connection():
    return mysql.connector.connect(
        host="yamanote.proxy.rlwy.net",
        user="root",
        password="rPwaOSqIAnqPGlZaArBxSCwURjqaDQFt",
        database="railway",
        port=17639
    )


# ================= BASIC HELPERS (IP, HASH, ACTIVITY) =================
def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_client_ip():
    if "X-Forwarded-For" in request.headers:
        ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
    else:
        ip = request.remote_addr or "0.0.0.0"
    return ip


def record_ip_activity(ip_hash: str, endpoint: str):
    """
    Requires table:
    CREATE TABLE ip_activity (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        client_ip_hash VARCHAR(64) NOT NULL,
        endpoint VARCHAR(100) NOT NULL,
        occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO ip_activity (client_ip_hash, endpoint) VALUES (%s, %s)",
            (ip_hash, endpoint),
        )
        db.commit()
    except Exception as e:
        print("record_ip_activity error:", e)
    finally:
        try:
            cursor.close()
            db.close()
        except Exception:
            pass


def count_ip_requests(ip_hash: str, endpoint: str, minutes: int) -> int:
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) FROM ip_activity
            WHERE client_ip_hash=%s
              AND endpoint=%s
              AND occurred_at >= (NOW() - INTERVAL %s MINUTE)
            """,
            (ip_hash, endpoint, minutes),
        )
        (cnt,) = cursor.fetchone()
        return cnt or 0
    except Exception as e:
        print("count_ip_requests error:", e)
        return 0
    finally:
        try:
            cursor.close()
            db.close()
        except Exception:
            pass


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

    # You already have email-verified.html, but current flow returns text.
    # Keeping as-is to avoid breaking frontend.
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

    client_ip = get_client_ip()
    ip_hash = hash_value(client_ip)

    # Rate limit for login attempts
    attempts = count_ip_requests(ip_hash, "login", 15)
    if attempts >= LOGIN_ATTEMPTS_PER_IP_PER_15MIN:
        return jsonify({"error": "Too many login attempts, please wait."}), 429

    record_ip_activity(ip_hash, "login")

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admins WHERE username=%s", (username,))
    user = cursor.fetchone()

    success = False

    if not user:
        # record failed attempt
        try:
            cursor2 = db.cursor()
            cursor2.execute(
                "INSERT INTO login_attempts (username, success, client_ip_hash) VALUES (%s, %s, %s)",
                (username, 0, ip_hash)
            )
            db.commit()
            cursor2.close()
        except Exception as e:
            print("login_attempts insert error:", e)

        cursor.close()
        db.close()
        return jsonify({"error": "Invalid credentials"}), 401

    if user["is_verified"] != 1:
        # record attempt
        try:
            cursor2 = db.cursor()
            cursor2.execute(
                "INSERT INTO login_attempts (username, success, client_ip_hash) VALUES (%s, %s, %s)",
                (username, 0, ip_hash)
            )
            db.commit()
            cursor2.close()
        except Exception as e:
            print("login_attempts insert error:", e)

        cursor.close()
        db.close()
        return jsonify({"error": "Please verify your email first"}), 403

    if not bcrypt.check_password_hash(user["password_hash"], password):
        try:
            cursor2 = db.cursor()
            cursor2.execute(
                "INSERT INTO login_attempts (username, success, client_ip_hash) VALUES (%s, %s, %s)",
                (username, 0, ip_hash)
            )
            db.commit()
            cursor2.close()
        except Exception as e:
            print("login_attempts insert error:", e)

        cursor.close()
        db.close()
        return jsonify({"error": "Invalid credentials"}), 401

    # success
    success = True
    try:
        cursor2 = db.cursor()
        cursor2.execute(
            "INSERT INTO login_attempts (username, success, client_ip_hash) VALUES (%s, %s, %s)",
            (username, 1, ip_hash)
        )
        db.commit()
        cursor2.close()
    except Exception as e:
        print("login_attempts insert error:", e)

    cursor.close()
    db.close()
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
        cursor.execute("""
            UPDATE form_templates
            SET name=%s, status=%s, data=%s
            WHERE id=%s
        """, (name, status, json_data, template_id))
    else:
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


# ================= PUBLIC FORM READ (SAFE VIEW) =================
@app.route("/get-public-form/<int:template_id>", methods=["GET"])
def get_public_form(template_id):
    """
    Returns a safe subset of the template for public rendering.
    Uses existing form_templates.data JSON, but requires status != 'draft'.
    """
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, status, data, domain, name FROM form_templates WHERE id=%s",
        (template_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    db.close()

    if not row:
        return jsonify({"error": "Form not found"}), 404

    if row["status"] == "draft":
        return jsonify({"error": "Form is not public"}), 403

    try:
        j = json.loads(row["data"])
    except Exception:
        j = {}

    safe = {
        "id": row["id"],
        "name": j.get("name", row["name"] or "Feedback Form"),
        "domain": j.get("domain", row["domain"] or "custom"),
        "services": j.get("services", []),
        "overallRating": j.get("overallRating", 0),
        "ratingReason": j.get("ratingReason", "")
    }
    return jsonify(safe), 200


# ================= FEEDBACK SENTIMENT / BIAS HELPERS =================
def classify_sentiment(overall_rating: int) -> str:
    if overall_rating <= 2:
        return "negative"
    if overall_rating == 3:
        return "neutral"
    return "positive"


def detect_biased_pattern(all_answers_text: str, overall_rating: int) -> bool:
    text_lower = all_answers_text.lower()
    short_negative = (
        overall_rating == 1 and len(text_lower.replace(" ", "")) < 10
    )
    generic_words = ["good", "ok", "fine", "normal", "nothing"]
    many_generic = sum(text_lower.count(w) for w in generic_words) >= 5
    rating_mismatch = overall_rating <= 2 and "good" in text_lower

    return short_negative or many_generic or rating_mismatch


# ================= SUBMIT FEEDBACK (ANONYMOUS) =================
@app.route("/submit-feedback", methods=["POST"])
def submit_feedback():
    """
    Expected JSON from public-form.html:
    {
      "form_id": 123,
      "overall_rating": 1-5,
      "rating_reason": "...",  # required if rating <=2
      "answers": [
         {
           "section_name": "...",
           "question_index": 0,
           "question_text": "...",
           "answer_type": "multiple" | "short" | "long" | "rating" | "yesno" | "checkbox" | "dropdown",
           "answer_value": "text or selected label(s)",
           "numeric_score": 1-5 (optional, for ratings)
         },
         ...
      ]
    }
    """
    payload = request.get_json() or {}
    form_id = payload.get("form_id")
    overall_rating = payload.get("overall_rating")
    rating_reason = (payload.get("rating_reason") or "").strip()
    answers = payload.get("answers") or []

    if not form_id or not overall_rating:
        return jsonify({"error": "Missing form_id or overall_rating"}), 400

    try:
        overall_rating = int(overall_rating)
    except ValueError:
        return jsonify({"error": "Invalid overall_rating"}), 400

    if overall_rating <= 2 and not rating_reason:
        return jsonify({"error": "Reason is required for low rating"}), 400

    client_ip = get_client_ip()
    ip_hash = hash_value(client_ip)
    ua_hash = hash_value(request.headers.get("User-Agent", "unknown"))

    # rate limit submissions per IP/hour
    feedback_last_hour = count_ip_requests(ip_hash, "submit-feedback", 60)
    if feedback_last_hour >= FEEDBACK_PER_IP_PER_HOUR:
        return jsonify({"error": "Too many submissions from your network. Try later."}), 429

    record_ip_activity(ip_hash, "submit-feedback")

    overall_sentiment = classify_sentiment(overall_rating)
    is_negative_flag = 1 if overall_sentiment == "negative" else 0

    all_text = " ".join([(a.get("answer_value") or "") for a in answers]) + " " + rating_reason
    is_biased_flag = 1 if detect_biased_pattern(all_text, overall_rating) else 0

    db = get_db_connection()
    cursor = db.cursor()

    # ensure form exists and is public
    cursor.execute("SELECT status FROM form_templates WHERE id=%s", (form_id,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        db.close()
        return jsonify({"error": "Form not found"}), 404
    if row[0] == "draft":
        cursor.close()
        db.close()
        return jsonify({"error": "Form is not public"}), 403

    try:
        # feedback_responses table must exist:
        # form_template_id, client_ip_hash, user_agent_hash, overall_rating, overall_sentiment,
        # is_negative_flag, is_biased_flag, raw_meta
        meta = {
            "rating_reason": rating_reason
        }
        cursor.execute(
            """
            INSERT INTO feedback_responses
              (form_template_id, client_ip_hash, user_agent_hash,
               overall_rating, overall_sentiment, is_negative_flag, is_biased_flag, raw_meta)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                form_id,
                ip_hash,
                ua_hash,
                overall_rating,
                overall_sentiment,
                is_negative_flag,
                is_biased_flag,
                json.dumps(meta)
            )
        )
        db.commit()
        feedback_id = cursor.lastrowid

        complaint_text_accum = []

        for ans in answers:
            section_name = ans.get("section_name") or ""
            question_index = int(ans.get("question_index") or 0)
            question_text = ans.get("question_text") or ""
            answer_type = ans.get("answer_type") or "short"
            answer_value = ans.get("answer_value") or ""
            numeric_score = ans.get("numeric_score")
            if numeric_score is not None:
                try:
                    numeric_score = int(numeric_score)
                except ValueError:
                    numeric_score = None

            is_complaint_flag = 0
            qt_lower = question_text.lower()
            if ("complaint" in qt_lower or "issue" in qt_lower or "problem" in qt_lower) and answer_value.strip():
                is_complaint_flag = 1
                complaint_text_accum.append(answer_value.strip())

            cursor.execute(
                """
                INSERT INTO feedback_answers
                    (feedback_response_id, section_name, question_index,
                     question_text, answer_type, answer_text, numeric_score, is_complaint_flag)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    feedback_id,
                    section_name,
                    question_index,
                    question_text,
                    answer_type,
                    answer_value,
                    numeric_score,
                    is_complaint_flag
                )
            )

        db.commit()

        if overall_rating <= 2:
            summary = rating_reason or "Negative rating without explicit reason."
            if complaint_text_accum:
                summary += " | Complaints: " + " | ".join(complaint_text_accum)
            cursor.execute(
                """
                INSERT INTO complaints
                  (feedback_response_id, form_template_id, overall_rating, summary)
                VALUES (%s, %s, %s, %s)
                """,
                (feedback_id, form_id, overall_rating, summary)
            )
            db.commit()

        cursor.close()
        db.close()
        return jsonify({"message": "Feedback submitted"}), 200

    except Exception as e:
        print("submit_feedback error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500


# ================= SIMPLE ADMIN ANALYTICS =================
@app.route("/admin/form-summary/<int:form_id>", methods=["GET"])
def form_summary(form_id):
    """
    Returns counts by sentiment, average rating, and complaint count.
    """
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
              COUNT(*) AS total,
              AVG(overall_rating) AS avg_rating,
              SUM(CASE WHEN overall_sentiment='negative' THEN 1 ELSE 0 END) AS negatives,
              SUM(CASE WHEN overall_sentiment='neutral' THEN 1 ELSE 0 END) AS neutrals,
              SUM(CASE WHEN overall_sentiment='positive' THEN 1 ELSE 0 END) AS positives
            FROM feedback_responses
            WHERE form_template_id=%s
            """,
            (form_id,),
        )
        summary = cursor.fetchone() or {}

        cursor.execute(
            "SELECT COUNT(*) AS complaints FROM complaints WHERE form_template_id=%s",
            (form_id,),
        )
        c_row = cursor.fetchone() or {}
        summary["complaints"] = c_row.get("complaints", 0)

        # convert Decimal to float where needed
        if summary.get("avg_rating") is not None:
            summary["avg_rating"] = float(summary["avg_rating"])

        cursor.close()
        db.close()
        return jsonify(summary), 200
    except Exception as e:
        print("form_summary error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
