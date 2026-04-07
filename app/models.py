from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from sqlalchemy import func
import pytz
import uuid
import hashlib
import secrets
from app.extensions import db
from sqlalchemy.dialects.postgresql import JSONB as JSON


def get_vietnam_time():
    """Lấy thời gian hiện tại theo múi giờ Việt Nam (UTC+7)"""
    utc_now = datetime.now(timezone.utc)
    vietnam_tz = pytz.timezone('Asia/Ho_Chi_Minh')
    return utc_now.astimezone(vietnam_tz).replace(tzinfo=None)

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100))
    email = db.Column(db.String(50), unique=True, nullable=False)
    phone = phone = db.Column(db.String(20))
    role = db.Column(db.String(25), nullable=False) 
    is_active = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer)
    api_key = db.Column(db.String(100), unique=True, default=lambda: str(uuid.uuid4()))
    created_at = db.Column(db.DateTime, default=get_vietnam_time)
    avatar = db.Column(db.String(255), nullable=True)
    biography = db.Column(db.String(500), nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    two_factor_method = db.Column(db.String(10), nullable=True) 
    # ------------------------------

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_otp(self, otp_code):
        """Lưu OTP dưới dạng hash và set thời gian hết hạn (ví dụ 5 phút)"""
        self.otp_hash = generate_password_hash(otp_code)
        # Lưu ý: cần tính toán thời gian dựa trên UTC hoặc VN time đồng bộ với server
        self.otp_expiry = get_vietnam_time() + timedelta(minutes=5)

    def check_otp(self, otp_code):
        """Kiểm tra OTP và thời gian hết hạn"""
        if not self.otp_hash or not self.otp_expiry:
            return False
        if get_vietnam_time() > self.otp_expiry:
            return False # OTP hết hạn
        return check_password_hash(self.otp_hash, otp_code)

class EmailVerificationToken(db.Model):
    __tablename__ = "email_verification_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="email_tokens")
    
    @staticmethod
    def generate_email_verification_token(user):
        # Xóa token cũ của user (chỉ giữ 1 active)
        EmailVerificationToken.query.filter_by(
            user_id=user.id,
            is_used=False
        ).delete()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        expires_at = datetime.utcnow() + timedelta(hours=1)

        token_obj = EmailVerificationToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at
        )

        db.session.add(token_obj)
        db.session.commit()
        print("TOKEN GỐC:", raw_token)
        print("HASH GỐC:", hashlib.sha256(raw_token.encode()).hexdigest())

        return raw_token


class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    login_time = db.Column(db.DateTime, default=get_vietnam_time)
    logout_time = db.Column(db.DateTime)
    session_duration = db.Column(db.Integer) # Thêm trường này vì trong code AuthService có dùng
    login_success = db.Column(db.Boolean, default=True)
    # Thêm status text để rõ ràng hơn (VD: SUCCESS, WRONG_PASS, PENDING_2FA, OTP_FAILED)
    status = db.Column(db.String(20), default="SUCCESS")
    
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    username = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45)) 
    category = db.Column(db.String(50), index=True)
    action = db.Column(db.String(50)) 
    target_type = db.Column(db.String(50))
    target_id = db.Column(db.Integer) 
    changes = db.Column(JSON) 
    description = db.Column(db.String(255)) # Mô tả ngắn gọn cho người đọc
    timestamp = db.Column(db.DateTime, default=get_vietnam_time, index=True)

class FailedLoginAttempt(db.Model):
    """Chặn Brute-force"""
    __tablename__ = 'failed_login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    attempt_time = db.Column(db.DateTime, default=get_vietnam_time)


class AccountBalance(db.Model):
    __tablename__ = 'account_balances'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    account_number = db.Column(db.String(16), unique=True, nullable=False, default=lambda: ''.join([str(__import__('random').randint(0,9)) for _ in range(16)]))
    balance = db.Column(db.Numeric(18, 2), nullable=False, default=0.00)
    currency = db.Column(db.String(3), default='VND')
    is_frozen = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=get_vietnam_time, onupdate=get_vietnam_time)
    created_at = db.Column(db.DateTime, default=get_vietnam_time)

    user = db.relationship('User', backref=db.backref('account', uselist=False))

    def can_transfer(self, amount):
        """Kiểm tra có đủ số dư và tài khoản không bị đóng băng"""
        return not self.is_frozen and self.balance >= amount

    def __repr__(self):
        return f'<AccountBalance user_id={self.user_id} balance={self.balance}>'


class TransactionLog(db.Model):
    __tablename__ = 'transaction_logs'

    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Numeric(18, 2), nullable=False)
    description = db.Column(db.String(255), nullable=True)

    # Trạng thái: PENDING → SUCCESS / FAILED / CANCELLED
    status = db.Column(db.String(20), default='PENDING')

    # 2FA tracking
    requires_2fa = db.Column(db.Boolean, default=True)
    two_fa_verified = db.Column(db.Boolean, default=False)
    two_fa_method = db.Column(db.String(10), nullable=True)  # 'otp' | 'totp' | None

    # Snapshot số dư tại thời điểm giao dịch (để audit)
    sender_balance_before = db.Column(db.Numeric(18, 2))
    sender_balance_after = db.Column(db.Numeric(18, 2))
    receiver_balance_before = db.Column(db.Numeric(18, 2))
    receiver_balance_after = db.Column(db.Numeric(18, 2))

    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=get_vietnam_time)
    completed_at = db.Column(db.DateTime, nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_transactions')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_transactions')

    def __repr__(self):
        return f'<Transaction {self.transaction_id} {self.status} {self.amount}>'