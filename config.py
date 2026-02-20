import os
from datetime import timedelta
from dotenv import load_dotenv

# Load biến từ file .env (chỉ dùng khi chạy local hoặc test, Docker sẽ tự nạp biến riêng)
load_dotenv()

class Config:
    # Lấy từ biến môi trường, nếu không có thì báo lỗi hoặc lấy None
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI') 
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_LOGIN_ATTEMPTS = 100
    LOGIN_LOCKOUT_SECONDS = 30

    # Log folder giữ nguyên, Docker sẽ map volume vào đây
    LOG_FOLDER = "logs"
    LOG_FILE = "app.log" # Đổi tên nếu muốn
    LOG_MAX_BYTES = 10 * 1024 * 1024
    LOG_BACKUP_COUNT = 5
    
    SECRET_KEY = os.getenv('SECRET_KEY', 'key-mặc-định-để-dev-không-bị-lỗi')

    # ==========================================
    # CẤU HÌNH SESSION & COOKIE
    # ==========================================
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_COOKIE_NAME = 'attmdt_session'
    SESSION_COOKIE_HTTPONLY = True 
    
    # Chuyển đổi chuỗi 'True'/'False' từ file env thành Boolean
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_SAMESITE = 'Lax'

    # ==========================================
    # CẤU HÌNH FLASK-LOGIN
    # ==========================================
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    REMEMBER_COOKIE_NAME = 'attmdt_remember'
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = os.getenv('REMEMBER_COOKIE_SECURE', 'False').lower() == 'true'
    
    MAIL_SERVER = os.getenv("MAIL_SERVER")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")
