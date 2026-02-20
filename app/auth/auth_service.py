from typing import Optional
import hashlib
from datetime import datetime, timezone, timedelta
from flask_login import login_user
from flask import session, current_app, request, jsonify
from app.routes.user.user_services import UserService
from app.auth.mail_service import send_otp_email
from app.extensions import db
from app.models import User, LoginLog, get_vietnam_time, EmailVerificationToken
from app.logs.logs_app import log_system, log_audit
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import redis_client
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from app.security.login_attemps import (
    get_failed_attempt_count, 
    is_account_locked, 
    record_failed_attempt, 
    clear_failed_attempts
)
OTP_EXPIRE_SECONDS = 300  # 5 phút

class LoginResult:
    def __init__(self, success: bool, message: Optional[str] = None, redirect_to: Optional[str] = None):
        self.success = success
        self.message = message
        self.redirect_to = redirect_to

class AuthService:
    @staticmethod
    def verify_email_token(raw_token):
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        token_obj = EmailVerificationToken.query.filter_by(
            token_hash=token_hash,
            is_used=False
        ).first()

        if not token_obj:
            return None

        if token_obj.expires_at < datetime.utcnow():
            return None

        user = token_obj.user

        # Đánh dấu đã dùng (chống replay)
        token_obj.is_used = True
        user.email_verified = True
        user.is_active = True

        db.session.commit()

        return user

    
    @staticmethod
    def generate_and_store_otp(user, purpose):
        otp = UserService._generate_otp_code()
        hashed = generate_password_hash(otp)
        key = f"otp:{purpose}:{user.id}"
        redis_client.setex(key, OTP_EXPIRE_SECONDS, hashed)
        send_otp_email(user, otp)
        return True
    
    
    
    def login(self, username, password, ip_address):
        # 1. KIỂM TRA KHÓA
        if is_account_locked(username, ip_address):
            self._handle_lockout(username, ip_address)
            return LoginResult(False, "Tài khoản bị khóa tạm thời. Vui lòng thử lại sau.")

        # 2. TÌM USER
        user = User.query.filter_by(username=username).first()

        # Case A: User không tồn tại
        if not user:
            log_system("WARNING", "Login failed: User not found", extra={"username": username, "ip": ip_address})
            return LoginResult(False, "Tên đăng nhập hoặc mật khẩu không đúng")

        # Case B: Sai Password
        if not user.check_password(password):
            return self._handle_failed_login(user, username, ip_address)

        # Case C: Xác thực email
        if not user.email_verified:
            return LoginResult(False, "Vui lòng xác thực email trước khi đăng nhập.")

        # Case D: Inactive
        if not user.is_active:
            log_system("WARNING", "Login blocked: Inactive user", extra={"username": username})
            return LoginResult(False, "Tài khoản này đang bị vô hiệu hóa.")

        # 3. PASSWORD ĐÚNG -> XỬ LÝ ĐĂNG NHẬP
        
        # NẾU CÓ 2FA
        if user.two_factor_method:
            # Ghi log trạng thái PENDING_2FA (chưa tính là success hẳn)
            login_log_id = self._save_login_history(user, ip_address, success=False, status="PENDING_2FA")
            
            self.generate_and_store_otp(user, purpose="login")

            return LoginResult(
                success=True,
                redirect_to="auth.otp_login_page",
                message={
                    "pre_2fa_user_id": user.id,
                    "pre_2fa_log_id": login_log_id
                }
            )

        # NẾU KHÔNG CÓ 2FA (Login luôn)
        login_user(user)
        login_log_id = self._save_login_history(user, ip_address, success=True, status="SUCCESS")
        
        # Lưu login_log_id vào session để dùng lúc logout
        session['login_log_id'] = login_log_id
        clear_failed_attempts(username, ip_address)
        log_system("INFO", "User logged in", extra={"user_id": user.id})
        return LoginResult(True, redirect_to="main.dashboard", message={
            "login_log_id": login_log_id
        })

    # Thêm hàm này vào class AuthService
    def logout(self, login_log_id):
        if not login_log_id: return
        try:
            log = LoginLog.query.get(login_log_id)
            if log:
                log.logout_time = get_vietnam_time()
                # Tính thời gian online
                if log.login_time:
                    delta = log.logout_time - log.login_time
                    log.session_duration = int(delta.total_seconds())
                db.session.commit()
                log_system("INFO", "User logout", extra={"user_id": log.user_id})
        except Exception as e:
            db.session.rollback()   # BẮT BUỘC
            log_system("ERROR", "Logout log failed",
                    extra={"error": str(e)})
            raise


    # --- BỔ SUNG HÀM CẬP NHẬT LOG KHI CHECK OTP ---
    @staticmethod
    def _update_login_history_status(log_id, success: bool, status: str = None):
        """Cập nhật trạng thái log sau khi verify OTP"""
        try:
            log = LoginLog.query.get(log_id)
            if log:
                log.login_success = success
                if status:
                    log.status = status
                db.session.commit()
        except Exception as e:
            db.session.rollback()
            log_system("ERROR", "Update login log failed", extra={"error": str(e)})

    # ==========================================
    # PRIVATE HELPERS
    # ==========================================

    def _handle_failed_login(self, user, username, ip):
        """Xử lý logic khi sai mật khẩu"""
        # 1. Ghi nhận lần sai vào Cache/Redis
        record_failed_attempt(username, ip)
        
        # 2. Ghi vào bảng LoginLog (DB) là thất bại
        self._save_login_history(user, ip, success=False, status="WRONG PASSWORD")
        
        # 3. Log warning ra hệ thống
        log_system("WARNING", "Login failed: Wrong password", extra={"user_id": user.id, "ip": ip})

        # 4. Tính toán số lần còn lại để báo user
        return LoginResult(False, self._remaining_attempt_message(username, ip))

    def _handle_lockout(self, username, ip):
        """Xử lý khi tài khoản chính thức bị khóa"""
        # Ghi log Audit quan trọng (Để Admin biết có người đang tấn công)
        log_audit(
            action="ACCOUNT_LOCKED",
            category="SECURITY",
            description=f"Tài khoản {username} bị khóa tạm thời do brute-force từ IP {ip}"
        )
        
        # Gửi cảnh báo (Email/Telegram) - Uncomment nếu có hàm gửi
        # send_security_alert(username, ip) 


    def _save_login_history(self, user, ip_address, success, status="SUCCESS"):
        try:
            ua = request.headers.get("User-Agent", "")
            user_agent = ua[:250] if ua else None
            log = LoginLog(
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                login_success=success,
                status=status,
                login_time=get_vietnam_time()
            )
            db.session.add(log)
            db.session.commit()
            return log.id
        except Exception as e:
            db.session.rollback()
            # Thêm dòng này để nhìn thấy lỗi ngay trên màn hình chạy server
            print(f"!!! DB ERROR: {str(e)}") 
            log_system("ERROR", "Failed to save login log", extra={"error": str(e)})
            return None

    def _remaining_attempt_message(self, username, ip):
        max_attempts = current_app.config.get("MAX_LOGIN_ATTEMPTS", 5)
        current = get_failed_attempt_count(username, ip)
        remaining = max_attempts - current
        return f"Mật khẩu không đúng! Còn {remaining} lần thử." if remaining > 0 else "Tài khoản bị khóa."
    
    
    # =========================================================================
    # 2. CÁC SERVICE CHO 2FA (Two-Factor Authentication)
    # =========================================================================

    @staticmethod
    def request_otp(user_id, purpose):
        user = User.query.get_or_404(user_id)
        return AuthService.generate_and_store_otp(user, purpose)

    
    @staticmethod
    def verify_login_otp_service(user_id, otp_code, login_log_id):

        user = User.query.get_or_404(user_id)

        key = f"otp:login:{user.id}"
        stored_hash = redis_client.get(key)

        if not stored_hash:
            return False, "OTP đã hết hạn hoặc không tồn tại."

        if not check_password_hash(stored_hash, otp_code):
            record_failed_attempt(f"otp:{user.id}", request.remote_addr)
            failed = get_failed_attempt_count(f"otp:{user.id}", request.remote_addr)

            if failed >= 5:
                redis_client.delete(key)
                return False, "LOCKED_OTP"

            return False, f"OTP sai. Còn {5 - failed} lần thử."

        # OTP đúng
        redis_client.delete(key)
        clear_failed_attempts(f"otp:{user.id}", request.remote_addr)

        login_user(user)

        if login_log_id:
            AuthService._update_login_history_status(login_log_id, True, "SUCCESS_2FA")

        return True, None

    @staticmethod
    def verify_otp_service(user_id, otp_code):

        user = User.query.get_or_404(user_id)

        key = f"otp:enable_2fa:{user.id}"
        stored_hash = redis_client.get(key)

        if not stored_hash:
            return False

        if not check_password_hash(stored_hash, otp_code):
            return False

        redis_client.delete(key)
        return True

        
    # =====================================================
    # TOGGLE 2FA
    # =====================================================
    @staticmethod
    def toggle_2fa_service(actor, user_id, enable: bool, method="email"):
        """
        Bật/Tắt 2FA.
        Cần xác thực lại mật khẩu hoặc OTP trước khi gọi hàm này ở Controller.
        """
        user = User.query.get_or_404(user_id)
        if actor.id != user.id and actor.role != 'admin':
            raise PermissionError("Không có quyền thay đổi cài đặt bảo mật này.")
        try:
            if enable:
                user.two_factor_method = method
                log_audit("SECURITY", "2FA", user, {}, f"Đã bật 2FA ({method})")
            else:
                user.two_factor_method = None
                log_audit("SECURITY", "2FA", user, {}, "Đã tắt 2FA")
            
            db.session.commit()
            return {"success": True, "status": "enabled" if enable else "disabled"}
            
        except Exception as e:
            db.session.rollback()
            raise e
        