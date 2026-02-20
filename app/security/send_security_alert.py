import smtplib
from email.mime.text import MIMEText  # SỬA LẠI: MIMEText thay vì MimeText
from email.mime.multipart import MIMEMultipart  # SỬA LẠI: MIMEMultipart thay vì MimeMultipart
from flask import current_app

current_app.config['MAIL_SERVER'] = 'smtp.gmail.com'
current_app.config['MAIL_PORT'] = 587
current_app.config['MAIL_USE_TLS'] = True
current_app.config['MAIL_USERNAME'] = 'thanhbadass@gmail.com'  # Thay bằng email của bạn
current_app.config['MAIL_PASSWORD'] = 'wawg hbfj dohk qxbl'     # Thay bằng mật khẩu app
current_app.config['MAIL_DEFAULT_SENDER'] = 'thanhbadass@gmail.com'

