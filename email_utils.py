from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer

BASE_URL = "https://web-production-315e.up.railway.app"

def send_verification_email(mail, app, email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = serializer.dumps(email, salt="email-verify")

    link = f"{BASE_URL}/verify/{token}"

    msg = Message(
        subject="Verify Your Admin Account",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email],
        body=f"Click the link to verify your account:\n\n{link}"
    )

    mail.send(msg)
