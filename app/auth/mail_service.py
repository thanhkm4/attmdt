import random
from flask_mail import Message
from flask import current_app, url_for
from app.extensions import mail
from app.models import User
from app.extensions import db

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(user: User, otp: str):

    msg = Message(
        subject="Mã xác thực đăng nhập (OTP)",
        recipients=[user.email]
    )

    msg.body = f"""
                Xin chào {user.full_name or user.username},

                Mã OTP của bạn là: {otp}

                Mã có hiệu lực trong 5 phút.
                Không chia sẻ mã này với bất kỳ ai.

                Trân trọng.
                """

    mail.send(msg)
    
def send_verification_email(user, token):
    verify_url = url_for("auth.verify_email", token=token, _external=True)

    msg = Message(
        subject="Thư xác thực Email",
        recipients=[user.email]
    )

    msg.body = f"""
                Xin chào {user.full_name or user.username},

                Vui lòng bấm vào link sau để xác thực tài khoản:

                {verify_url}

                Link có hiệu lực trong 1 giờ.
                Trân trọng.
                """

    mail.send(msg)
    

