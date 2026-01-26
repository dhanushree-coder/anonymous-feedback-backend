from flask_mail import Message

BASE_URL = "https://web-production-315e.up.railway.app"

def send_verification_email(mail, app, token, email):
    link = f"{BASE_URL}/verify/{token}"

    msg = Message(
        subject="Verify Your Admin Account",
        sender=app.config['MAIL_DEFAULT_SENDER'],  # ✅ correct sender
        recipients=[email],
        body=f"Click the link to verify your account:\n\n{link}"
    )

    mail.send(msg)

