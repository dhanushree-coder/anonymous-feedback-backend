from flask import Flask, request, jsonify, redirect, send_file
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import mysql.connector
import os
import json
import hashlib
from datetime import datetime
import io

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SGMail

import pdfkit  # for PDF generation
import csv     # for CSV report generation

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

    attempts = count_ip_requests(ip_hash, "login", 15)
    if attempts >= LOGIN_ATTEMPTS_PER_IP_PER_15MIN:
        return jsonify({"error": "Too many login attempts, please wait."}), 429

    record_ip_activity(ip_hash, "login")

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admins WHERE username=%s", (username,))
    user = cursor.fetchone()

    if not user:
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
    template_id = data.get("id")

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

# ================= STRICT CHECK: FEEDBACK STATUS BY IP =================
@app.route("/check-feedback-status", methods=["GET"])
def check_feedback_status():
    form_id = request.args.get("form_id", type=int)
    if not form_id:
        return jsonify({"error": "form_id is required"}), 400

    client_ip = get_client_ip()
    ip_hash = hash_value(client_ip)

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM feedback_responses
        WHERE form_template_id=%s AND client_ip_hash=%s
        """,
        (form_id, ip_hash),
    )
    (count,) = cursor.fetchone()
    cursor.close()
    db.close()

    return jsonify({"already_submitted": count > 0}), 200

# ================= SUBMIT FEEDBACK (ANONYMOUS) =================
@app.route("/submit-feedback", methods=["POST"])
def submit_feedback():
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

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM feedback_responses
        WHERE form_template_id=%s AND client_ip_hash=%s
        """,
        (form_id, ip_hash),
    )
    (already_submitted_count,) = cursor.fetchone()
    if already_submitted_count > 0:
        try:
            cursor.execute(
                """
                INSERT INTO blocked_feedback_attempts
                  (form_template_id, client_ip_hash, user_agent_hash, blocked_reason)
                VALUES (%s, %s, %s, %s)
                """,
                (form_id, ip_hash, ua_hash, "duplicate_ip"),
            )
            db.commit()
        except Exception as e:
            print("blocked_feedback_attempts insert error (duplicate_ip):", e)

        cursor.close()
        db.close()
        return jsonify({"error": "already_submitted"}), 429

    feedback_last_hour = count_ip_requests(ip_hash, "submit-feedback", 60)
    if feedback_last_hour >= FEEDBACK_PER_IP_PER_HOUR:
        try:
            cursor.execute(
                """
                INSERT INTO blocked_feedback_attempts
                  (form_template_id, client_ip_hash, user_agent_hash, blocked_reason)
                VALUES (%s, %s, %s, %s)
                """,
                (form_id, ip_hash, ua_hash, "rate_limit"),
            )
            db.commit()
        except Exception as e:
            print("blocked_feedback_attempts insert error (rate_limit):", e)

        cursor.close()
        db.close()
        return jsonify({"error": "Too many submissions from your network. Try later."}), 429

    record_ip_activity(ip_hash, "submit-feedback")

    overall_sentiment = classify_sentiment(overall_rating)
    is_negative_flag = 1 if overall_sentiment == "negative" else 0

    all_text = " ".join([(a.get("answer_value") or "") for a in answers]) + " " + rating_reason
    is_biased_flag = 1 if detect_biased_pattern(all_text, overall_rating) else 0

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

# ================= SIMPLE ADMIN ANALYTICS (LEGACY) =================
@app.route("/admin/form-summary/<int:form_id>", methods=["GET"])
def form_summary(form_id):
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

# ================= ADMIN FORMS SUMMARY (FOR DASHBOARD FORMS TAB) =================
@app.route("/admin/forms-summary", methods=["GET"])
def admin_forms_summary():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
              ft.id,
              ft.name,
              ft.status,
              COUNT(fr.id) AS submissions
            FROM form_templates ft
            LEFT JOIN feedback_responses fr
              ON fr.form_template_id = ft.id
            GROUP BY ft.id, ft.name, ft.status
            ORDER BY ft.updated_at DESC
            """
        )
        rows = cursor.fetchall()
        cursor.close()
        db.close()
        return jsonify(rows), 200
    except Exception as e:
        print("admin_forms_summary error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= ADMIN RECENT FEEDBACKS (FOR HOME) =================
@app.route("/admin/recent-feedbacks", methods=["GET"])
def admin_recent_feedbacks():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
              fr.id,
              fr.form_template_id,
              fr.overall_rating,
              fr.overall_sentiment,
              fr.submitted_at AS submitted_at,
              ft.name AS form_name
            FROM feedback_responses fr
            JOIN form_templates ft ON ft.id = fr.form_template_id
            ORDER BY fr.submitted_at DESC
            LIMIT 10
            """
        )
        rows = cursor.fetchall()
        cursor.close()
        db.close()
        return jsonify(rows), 200
    except Exception as e:
        print("admin_recent_feedbacks error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= ADMIN ALL FEEDBACKS (FOR FEEDBACKS TAB) =================
@app.route("/admin/all-feedbacks", methods=["GET"])
def admin_all_feedbacks():
    date = request.args.get("date")
    form = request.args.get("form")
    rating = request.args.get("rating")

    where_clauses = []
    params = []

    if date:
        where_clauses.append("DATE(fr.submitted_at) = %s")
        params.append(date)
    if form:
        where_clauses.append("(ft.name LIKE %s OR ft.id = %s)")
        params.append(f"%{form}%")
        try:
            params.append(int(form))
        except ValueError:
            params.append(0)
    if rating:
        where_clauses.append("fr.overall_rating = %s")
        params.append(int(rating))

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        sql = f"""
            SELECT
              fr.id,
              fr.form_template_id,
              fr.overall_rating,
              fr.overall_sentiment,
              fr.submitted_at AS submitted_at,
              ft.name AS form_name
            FROM feedback_responses fr
            JOIN form_templates ft ON ft.id = fr.form_template_id
            {where_sql}
            ORDER BY fr.submitted_at DESC
            LIMIT 100
        """
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        cursor.close()
        db.close()
        return jsonify(rows), 200
    except Exception as e:
        print("admin_all_feedbacks error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= FORM ANALYTICS SUMMARY (FOR form-analytics.html) =================
@app.route("/admin/form-analytics/summary", methods=["GET"])
def admin_form_analytics_summary():
    form_id = request.args.get("form_id", type=int)
    if not form_id:
        return jsonify({"error": "form_id is required"}), 400

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
              COUNT(*) AS total,
              AVG(overall_rating) AS avg_rating,
              SUM(CASE WHEN overall_sentiment='negative' THEN 1 ELSE 0 END) AS negatives,
              SUM(CASE WHEN overall_sentiment='positive' THEN 1 ELSE 0 END) AS positives
            FROM feedback_responses
            WHERE form_template_id=%s
            """,
            (form_id,),
        )
        summary = cursor.fetchone() or {}
        total = summary.get("total") or 0
        positives = summary.get("positives") or 0
        negatives = summary.get("negatives") or 0
        avg_rating = summary.get("avg_rating")
        if avg_rating is not None:
            summary["avg_rating"] = float(avg_rating)

        cursor.execute(
            "SELECT name FROM form_templates WHERE id=%s",
            (form_id,),
        )
        frow = cursor.fetchone()
        summary["form_name"] = frow["name"] if frow else f"Form {form_id}"

        cursor.execute(
            """
            SELECT summary AS reason_text, COUNT(*) AS count
            FROM complaints
            WHERE form_template_id=%s
            GROUP BY summary
            ORDER BY COUNT(*) DESC
            LIMIT 10
            """,
            (form_id,),
        )
        negative_reasons = cursor.fetchall()

        cursor.execute(
            """
            SELECT COUNT(*) AS attempts
            FROM ip_activity
            WHERE endpoint='submit-feedback'
            """,
        )
        total_attempts_row = cursor.fetchone() or {"attempts": 0}
        total_attempts = total_attempts_row.get("attempts") or 0

        blocked_attempts = max(total_attempts - total * 1, 0)

        cursor.execute(
            """
            SELECT client_ip_hash,
                   COUNT(*) AS attempts,
                   MIN(occurred_at) AS first_blocked,
                   MAX(occurred_at) AS last_blocked,
                   GROUP_CONCAT(DISTINCT blocked_reason) AS reasons
            FROM blocked_feedback_attempts
            WHERE form_template_id=%s
            GROUP BY client_ip_hash
            ORDER BY last_blocked DESC
            LIMIT 20
            """,
            (form_id,),
        )
        blocked_ips = cursor.fetchall()

        cursor.execute(
            """
            SELECT estimated_submissions
            FROM estimated_form_submissions
            WHERE form_template_id=%s
            """,
            (form_id,),
        )
        est_row = cursor.fetchone()
        estimated = est_row["estimated_submissions"] if est_row else None

        result = {
            "form_name": summary["form_name"],
            "total": total,
            "avg_rating": summary.get("avg_rating") or 0,
            "positives": positives,
            "negatives": negatives,
            "negative_reasons": negative_reasons,
            "blocked_attempts": blocked_attempts,
            "estimated_submissions": estimated,
            "blocked_ips": blocked_ips,
        }

        cursor.close()
        db.close()
        return jsonify(result), 200
    except Exception as e:
        print("admin_form_analytics_summary error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= FORM ANALYTICS PATTERNS (KEYWORDS & SECTIONS) =================
@app.route("/admin/form-analytics/patterns", methods=["GET"])
def admin_form_analytics_patterns():
    form_id = request.args.get("form_id", type=int)
    if not form_id:
        return jsonify({"error": "form_id is required"}), 400

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT fa.answer_text
            FROM feedback_answers fa
            JOIN feedback_responses fr ON fr.id = fa.feedback_response_id
            WHERE fr.form_template_id=%s
              AND (fr.overall_sentiment='negative' OR fa.is_complaint_flag=1)
            """,
            (form_id,),
        )
        rows = cursor.fetchall()
        word_counts = {}
        for r in rows:
            text = (r["answer_text"] or "").lower()
            for w in text.replace(",", " ").replace(".", " ").split():
                if len(w) < 4:
                    continue
                word_counts[w] = word_counts.get(w, 0) + 1

        keywords = sorted(
            [{"word": w, "count": c} for w, c in word_counts.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:10]

        cursor.execute(
            """
            SELECT
              fa.section_name,
              SUM(
                CASE
                  WHEN fa.numeric_score IS NOT NULL AND fa.numeric_score <= 2 THEN 1
                  ELSE 0
                END
              ) +
              SUM(CASE WHEN fa.is_complaint_flag=1 THEN 2 ELSE 0 END) AS issue_score
            FROM feedback_answers fa
            JOIN feedback_responses fr ON fr.id = fa.feedback_response_id
            WHERE fr.form_template_id=%s
            GROUP BY fa.section_name
            """,
            (form_id,),
        )
        section_rows = cursor.fetchall()

        result = {
            "keywords": keywords,
            "sections": section_rows,
        }

        cursor.close()
        db.close()
        return jsonify(result), 200
    except Exception as e:
        print("admin_form_analytics_patterns error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= ESTIMATED SUBMISSIONS SAVE =================
@app.route("/admin/form-analytics/estimated", methods=["POST"])
def admin_form_analytics_estimated():
    data = request.get_json() or {}
    form_id = data.get("form_id")
    estimated = data.get("estimated_submissions")

    if not form_id:
        return jsonify({"error": "form_id is required"}), 400

    if estimated is None:
        return jsonify({"error": "estimated_submissions is required"}), 400

    try:
        estimated = int(estimated)
        if estimated < 0:
            return jsonify({"error": "estimated_submissions cannot be negative"}), 400
    except ValueError:
        return jsonify({"error": "estimated_submissions must be integer"}), 400

    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO estimated_form_submissions (form_template_id, estimated_submissions)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE estimated_submissions=VALUES(estimated_submissions)
            """,
            (form_id, estimated),
        )
        db.commit()
        cursor.close()
        db.close()
        return jsonify({"success": True}), 200
    except Exception as e:
        print("admin_form_analytics_estimated error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= ADMIN USERS SUMMARY (FOR USERS TAB) =================
@app.route("/admin/users-summary", methods=["GET"])
def admin_users_summary():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
              client_ip_hash,
              COUNT(*) AS total_submissions,
              MAX(submitted_at) AS last_submission
            FROM feedback_responses
            GROUP BY client_ip_hash
            ORDER BY last_submission DESC
            LIMIT 100
            """
        )
        rows = cursor.fetchall()
        cursor.close()
        db.close()
        return jsonify(rows), 200
    except Exception as e:
        print("admin_users_summary error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= FEEDBACK DETAILS (FOR VIEW RESPONSE PAGE) =================
@app.route("/admin/feedback/<int:response_id>", methods=["GET"])
def admin_feedback_details(response_id):
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
              fr.id,
              fr.form_template_id,
              fr.client_ip_hash,
              fr.overall_rating,
              fr.overall_sentiment,
              fr.saved_flag,
              fr.submitted_at AS submitted_at,
              ft.name AS form_name
            FROM feedback_responses fr
            JOIN form_templates ft ON ft.id = fr.form_template_id
            WHERE fr.id = %s
            """,
            (response_id,),
        )
        resp = cursor.fetchone()
        if not resp:
            cursor.close()
            db.close()
            return jsonify({"error": "Response not found"}), 404

        cursor.execute(
            """
            SELECT
              section_name,
              question_text,
              answer_text
            FROM feedback_answers
            WHERE feedback_response_id=%s
            ORDER BY section_name, question_index ASC
            """,
            (response_id,),
        )
        answers = cursor.fetchall()

        result = resp
        result["answers"] = answers

        cursor.close()
        db.close()
        return jsonify(result), 200
    except Exception as e:
        print("admin_feedback_details error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= FEEDBACK SAVE FLAG =================
@app.route("/admin/feedback/<int:response_id>/save", methods=["POST"])
def admin_feedback_save(response_id):
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute(
            """
            UPDATE feedback_responses
            SET saved_flag = 1
            WHERE id = %s
            """,
            (response_id,),
        )
        db.commit()
        if cursor.rowcount == 0:
            cursor.close()
            db.close()
            return jsonify({"error": "Response not found"}), 404

        cursor.close()
        db.close()
        return jsonify({"success": True}), 200
    except Exception as e:
        print("admin_feedback_save error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= FEEDBACK DELETE =================
@app.route("/admin/feedback/<int:response_id>/delete", methods=["POST"])
def admin_feedback_delete(response_id):
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM complaints WHERE feedback_response_id=%s", (response_id,))
        cursor.execute("DELETE FROM feedback_answers WHERE feedback_response_id=%s", (response_id,))
        cursor.execute("DELETE FROM feedback_responses WHERE id=%s", (response_id,))
        db.commit()
        if cursor.rowcount == 0:
            cursor.close()
            db.close()
            return jsonify({"error": "Response not found"}), 404
        cursor.close()
        db.close()
        return jsonify({"success": True}), 200
    except Exception as e:
        print("admin_feedback_delete error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= REPORTS: LIST FORMS WITH RESPONSES =================
@app.route("/admin/reports/forms", methods=["GET"])
def admin_reports_forms():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT
              ft.id,
              ft.name,
              ft.created_at,
              COUNT(fr.id) AS total_submissions,
              AVG(fr.overall_rating) AS avg_rating
            FROM form_templates ft
            JOIN feedback_responses fr ON fr.form_template_id = ft.id
            WHERE ft.status = 'published'
            GROUP BY ft.id, ft.name, ft.created_at
            HAVING total_submissions > 0
            ORDER BY ft.updated_at DESC
            """
        )
        rows = cursor.fetchall()
        for r in rows:
            if r.get("avg_rating") is not None:
                r["avg_rating"] = float(r["avg_rating"])
        cursor.close()
        db.close()
        return jsonify(rows), 200
    except Exception as e:
        print("admin_reports_forms error:", e)
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
        return jsonify({"error": "Server error"}), 500

# ================= REPORTS: CSV DOWNLOAD PER FORM =================
@app.route("/admin/reports/<int:form_id>/csv", methods=["GET"])
def admin_reports_csv(form_id):
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, name FROM form_templates WHERE id=%s",
            (form_id,),
        )
        form_row = cursor.fetchone()
        if not form_row:
            cursor.close()
            db.close()
            return jsonify({"error": "Form not found"}), 404

        cursor.execute(
            """
            SELECT
              fr.id AS response_id,
              fr.submitted_at,
              fr.overall_rating,
              fr.overall_sentiment,
              fa.section_name,
              fa.question_text,
              fa.answer_text
            FROM feedback_responses fr
            LEFT JOIN feedback_answers fa ON fa.feedback_response_id = fr.id
            WHERE fr.form_template_id=%s
            ORDER BY fr.submitted_at DESC, fa.section_name, fa.question_index
            """,
            (form_id,),
        )
        rows = cursor.fetchall()
        cursor.close()
        db.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "response_id", "submitted_at", "overall_rating", "overall_sentiment",
            "section_name", "question_text", "answer_text"
        ])
        for r in rows:
            writer.writerow([
                r.get("response_id"),
                r.get("submitted_at"),
                r.get("overall_rating"),
                r.get("overall_sentiment"),
                r.get("section_name") or "",
                r.get("question_text") or "",
                r.get("answer_text") or "",
            ])

        csv_bytes = io.BytesIO(output.getvalue().encode("utf-8"))
        filename = f"feedback_report_form_{form_id}.csv"
        return send_file(
            csv_bytes,
            as_attachment=True,
            download_name=filename,
            mimetype="text/csv"
        )
    except Exception as e:
        print("admin_reports_csv error:", e)
        return jsonify({"error": "Failed to generate CSV report"}), 500

# ================= REPORTS: PDF DOWNLOAD PER FORM =================
@app.route("/admin/reports/<int:form_id>/pdf", methods=["GET"])
def admin_reports_pdf(form_id):
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, name, status, domain FROM form_templates WHERE id=%s",
            (form_id,),
        )
        form_row = cursor.fetchone()
        if not form_row:
            cursor.close()
            db.close()
            return jsonify({"error": "Form not found"}), 404

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
            """
            SELECT summary, overall_rating
            FROM complaints
            WHERE form_template_id=%s
            ORDER BY id DESC
            LIMIT 20
            """,
            (form_id,),
        )
        complaints_rows = cursor.fetchall()

        cursor.execute(
            """
            SELECT
              fa.section_name,
              fa.question_text,
              fa.answer_text,
              fr.overall_rating,
              fr.overall_sentiment
            FROM feedback_answers fa
            JOIN feedback_responses fr ON fr.id = fa.feedback_response_id
            WHERE fr.form_template_id=%s
            ORDER BY fr.submitted_at DESC, fa.section_name, fa.question_index
            LIMIT 100
            """,
            (form_id,),
        )
        sample_answers = cursor.fetchall()

        cursor.close()
        db.close()

        total = summary.get("total") or 0
        avg_rating = summary.get("avg_rating") or 0
        negatives = summary.get("negatives") or 0
        neutrals = summary.get("neutrals") or 0
        positives = summary.get("positives") or 0

        html_parts = []
        html_parts.append("<html><head><meta charset='utf-8'><style>")
        html_parts.append("body { font-family: Arial, sans-serif; font-size: 12px; }")
        html_parts.append("h1, h2, h3 { color: #222; }")
        html_parts.append("table { width: 100%; border-collapse: collapse; margin-bottom: 10px; }")
        html_parts.append("th, td { border: 1px solid #ccc; padding: 4px 6px; text-align: left; }")
        html_parts.append(".small { font-size: 10px; color: #555; }")
        html_parts.append("</style></head><body>")

        html_parts.append(f"<h1>Feedback Report - {form_row.get('name') or 'Form ' + str(form_id)}</h1>")
        html_parts.append(f"<p class='small'>Form ID: {form_row['id']} | Domain: {form_row.get('domain') or '-'} | Status: {form_row.get('status')}</p>")
        html_parts.append(f"<p>Date generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} (UTC)</p>")

        html_parts.append("<h2>Summary</h2>")
        html_parts.append("<table>")
        html_parts.append("<tr><th>Total Submissions</th><th>Average Rating</th><th>Positive</th><th>Neutral</th><th>Negative</th></tr>")
        html_parts.append(f"<tr><td>{total}</td><td>{round(float(avg_rating), 2) if avg_rating else 0.0}</td><td>{positives}</td><td>{neutrals}</td><td>{negatives}</td></tr>")
        html_parts.append("</table>")

        html_parts.append("<h2>Recent Complaints & Negative Highlights</h2>")
        if complaints_rows:
            html_parts.append("<table>")
            html_parts.append("<tr><th>Rating</th><th>Summary</th></tr>")
            for c in complaints_rows:
                html_parts.append(f"<tr><td>{c.get('overall_rating')}</td><td>{c.get('summary')}</td></tr>")
            html_parts.append("</table>")
        else:
            html_parts.append("<p>No recorded complaints for this form.</p>")

        html_parts.append("<h2>Sample Answers (up to 100)</h2>")
        if sample_answers:
            html_parts.append("<table>")
            html_parts.append("<tr><th>Section</th><th>Question</th><th>Answer</th><th>Rating</th><th>Sentiment</th></tr>")
            for a in sample_answers:
                html_parts.append(
                    f"<tr><td>{a.get('section_name') or '-'}</td>"
                    f"<td>{a.get('question_text') or '-'}</td>"
                    f"<td>{a.get('answer_text') or '-'}</td>"
                    f"<td>{a.get('overall_rating') or '-'}</td>"
                    f"<td>{a.get('overall_sentiment') or '-'}</td></tr>"
                )
            html_parts.append("</table>")
        else:
            html_parts.append("<p>No sample answers available.</p>")

        html_parts.append("<p class='small'>This is an auto-generated report for internal use by the administrator.</p>")
        html_parts.append("</body></html>")

        html_content = "".join(html_parts)

        pdf = pdfkit.from_string(html_content, False)
        pdf_stream = io.BytesIO(pdf)

        filename = f"feedback_report_form_{form_id}.pdf"
        return send_file(
            pdf_stream,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf"
        )
    except Exception as e:
        print("admin_reports_pdf error:", e)
        return jsonify({"error": "Failed to generate PDF report"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
