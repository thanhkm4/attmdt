import time
import re
import uuid
import random
import string
from sqlalchemy import or_
from app.extensions import db
from app.models import User, AccountBalance, TransactionLog
from app.logs.logs_app import log_audit, log_system
from flask_login import logout_user
from app.auth.mail_service import send_otp_email # Nhớ import hàm gửi mail của bạn
from app.extensions import redis_client
from werkzeug.security import generate_password_hash, check_password_hash
   


# Import các hàm check quyền cơ bản (Bạn tự điều chỉnh lại policy cho phù hợp với model mới)
from app.auth.policy import check_user
import os
from werkzeug.utils import secure_filename
from uuid import uuid4

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

UPLOAD_FOLDER = os.path.join("static", "uploads", "avatars")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class UserService:

    # =========================================================================
    # HELPERS
    # =========================================================================
    
    @staticmethod
    def _parse_bool(value):
        if isinstance(value, bool): return value
        if isinstance(value, str): return value.lower() in ("true", "1", "yes", "on")
        return False
    
    @staticmethod
    def is_valid_email(email):
        # Regex chuẩn RFC 5322 cơ bản nhưng an toàn cho Web
        regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(regex, email):
            return True
        return False
    
    @staticmethod
    def is_valid_vietnam_phone(phone):
        if not phone:
            return False
        # Regex giải thích:
        # ^0: Bắt đầu bằng số 0
        # (3|5|7|8|9): Số thứ hai phải là một trong các số này (các đầu số di động)
        # [0-9]{8}: 8 chữ số tiếp theo là bất kỳ số nào từ 0-9
        # $: Kết thúc chuỗi
        phone_regex = r"^(03|05|07|08|09)[0-9]{8}$"
        return bool(re.match(phone_regex, phone))
    
    @staticmethod
    def _generate_otp_code(length=6):
        """Tạo mã OTP ngẫu nhiên gồm 6 chữ số"""
        return ''.join(random.choices(string.digits, k=length))

    @staticmethod
    def _check_unique(data, user_id=None):
        """Check trùng Username/Email/Phone"""
        checks = {"username": "Username", "email": "Email", "phone": "SĐT"}
        for field, label in checks.items():
            value = data.get(field)
            if value:
                query = User.query.filter(getattr(User, field) == value)
                # Bỏ qua các user đã xóa mềm
                query = query.filter(User.username.notilike("deleted_%"))
                if user_id:
                    query = query.filter(User.id != user_id)
                if query.first():
                    raise ValueError(f"{label} '{value}' đã tồn tại.")

    # =========================================================================
    # 1. QUẢN LÝ USER CƠ BẢN (CRUD)
    # =========================================================================
    
    @staticmethod
    def register_user_service(data: dict):
        required = ["username", "email", "password"]
        for f in required:
            if not data.get(f):
                raise ValueError(f"Thiếu trường {f}")

        # Check unique
        if User.query.filter_by(username=data["username"]).first():
            raise ValueError("Username đã tồn tại")

        if User.query.filter_by(email=data["email"]).first():
            raise ValueError("Email đã tồn tại")

        try:
            user = User(
                username=data["username"],
                email=data["email"],
                role="user",  # cố định
                is_active=False,
                email_verified=False,
                
            )

            user.set_password(data["password"])

            db.session.add(user)
            db.session.flush()
            
            new_account = AccountBalance(
                user_id=user.id,
                balance=100000000.00,  # 100,000,000 VND
                currency='VND',
                is_frozen=False
            )
            db.session.add(new_account)

            # Chốt cả 2 thao tác (tạo User + tạo Account) vào database
            db.session.commit()

            return user

        except Exception as e:
            db.session.rollback()
            raise e

    
    @staticmethod
    def create_user_service(actor, data: dict):
        # 1. Validate dữ liệu đầu vào
        required = ["username", "email", "password", "role"]
        for f in required:
            if not data.get(f): raise ValueError(f"Thiếu trường {f}")
            
        UserService._check_unique(data)
        
        # 2. Check quyền (Policy)
        res = check_user(actor, data["role"]) 
        if not res.ok: raise PermissionError(res.reason)

        try:
            # 3. Tạo User
            user = User(
                username=data["username"],
                email=data["email"],
                phone=data.get("phone"),
                full_name=data.get("full_name"),
                role=data["role"],
                is_active=True, # Mặc định active
                created_by=actor.id if actor else None
            )
            user.set_password(data["password"])
            
            db.session.add(user)
            db.session.commit()

            # 4. Log
            log_audit("CREATE", "USER", user, {}, f"Tạo mới user {user.username}")
            return user

        except Exception as e:
            db.session.rollback()
            raise e

    @staticmethod
    def update_user_service(actor, user_id, data: dict):
        user = User.query.get_or_404(user_id)
        
        # Check quyền
        res = check_user(actor, user)
        if not res.ok: raise PermissionError(res.reason)

        UserService._check_unique(data, user_id)

        # Update fields
        if "full_name" in data: user.full_name = data["full_name"]
        if "email" in data: user.email = data["email"]
        if "phone" in data: user.phone = data["phone"]
        
        # Admin reset password logic
        if "password" in data and data["password"]:
            if actor.role == 'admin': # Chỉ admin mới được reset pass người khác
                user.set_password(data["password"])
                # Khi đổi pass, nên tắt 2FA để tránh bị lock nếu mất thiết bị
                user.two_factor_method = None 
                log_system("WARNING", f"Admin {actor.username} reset pass & disable 2FA for {user.username}")

        try:
            db.session.commit()
            return user
        except Exception as e:
            db.session.rollback()
            raise e

    @staticmethod
    def delete_user_service(actor, user_id):
        user = User.query.get_or_404(user_id)
        
        res = check_user(actor, user)
        if not res.ok: raise PermissionError(res.reason)

        try:
            # Soft Delete (Anonymize)
            ts = int(time.time())
            user.username = f"deleted_{user.id}_{ts}"
            user.email = f"del_{user.id}_{ts}@deleted.local"
            user.phone = None
            user.is_active = False
            user.two_factor_method = None # Tắt 2FA
            
            log_audit("DELETE", "USER", user, {}, f"Đã xóa user ID {user_id}")
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

    @staticmethod
    def get_user_detail_service(actor, user_id):
        """
        Lấy toàn bộ thông tin user (an toàn để trả ra UI).
        - User thường: chỉ xem được chính mình
        - Admin: xem được tất cả
        """
        user = User.query.get_or_404(user_id)

        # Check quyền
        if actor.id != user.id and actor.role != "admin":
            raise PermissionError("Không có quyền xem thông tin người dùng này.")

        account = user.account

        return {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "is_active": user.is_active,
            "created_by": user.created_by,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "biography": user.biography,
            "avatar": user.avatar,
            "two_factor_enabled": True if user.two_factor_method else False,
            "two_factor_method": user.two_factor_method,
            
            # --- BỔ SUNG THÔNG TIN SỐ DƯ ---
            "balance": float(account.balance) if account else 0.0,
            "currency": account.currency if account else "VND",
            "account_number": account.account_number if account else None
        }

    @staticmethod
    def allowed_file(filename):
        return "." in filename and \
               filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

    @staticmethod
    def upload_avatar_service(actor, file):

        if not file:
            raise ValueError("Không có file được tải lên.")

        if not UserService.allowed_file(file.filename):
            raise ValueError("Định dạng ảnh không hợp lệ.")

        # Generate filename an toàn
        ext = file.filename.rsplit(".", 1)[1].lower()
        filename = f"{uuid4().hex}.{ext}"

        filepath = os.path.join(UPLOAD_FOLDER, filename)

        file.save(filepath)

        # Nếu có avatar cũ thì xóa (tránh rác)
        if actor.avatar:
            old_path = actor.avatar.replace("/", os.sep)
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except:
                    pass

        # Lưu đường dẫn DB
        actor.avatar = f"/static/uploads/avatars/{filename}"
        db.session.commit()

        return actor.avatar
    
    @staticmethod
    def change_password_service(user_id, data, actor):
        if actor.id != user_id:
            raise PermissionError("Không có quyền thực hiện hành động này.")

        user = User.query.get(user_id)
        if not user:
            raise ValueError("Người dùng không tồn tại.")

        current_password = data.get("current_password")
        new_password = data.get("new_password")

        if not current_password or not new_password:
            raise ValueError("Thiếu dữ liệu.")

        # Kiểm tra mật khẩu hiện tại
        if not user.check_password(current_password):
            raise ValueError("Mật khẩu hiện tại không đúng.")

        # Kiểm tra mật khẩu mới không trùng
        if user.check_password(new_password):
            raise ValueError("Mật khẩu mới không được trùng mật khẩu cũ.")

        # Validate độ mạnh
        if len(new_password) < 8:
            raise ValueError("Mật khẩu phải tối thiểu 8 ký tự.")

        # Set mật khẩu mới
        user.set_password(new_password)

        db.session.commit()
        logout_user()
        return True
    
    
    # =========================================================================
    # 2. GIAO DỊCH & TÀI KHOẢN (TRANSACTIONS)
    # =========================================================================

    @staticmethod
    def check_account_service(account_number: str):
        """Truy vấn tên người dùng dựa vào số tài khoản"""
        if not account_number:
            raise ValueError("Vui lòng cung cấp số tài khoản.")

        account = AccountBalance.query.filter_by(account_number=account_number).first()
        if not account:
            raise ValueError("Không tìm thấy số tài khoản này trong hệ thống.")

        user = account.user
        if not user:
            raise ValueError("Tài khoản không hợp lệ (Không có chủ sở hữu).")

        return {
            "full_name": user.full_name or user.username,
            "username": user.username
        }

    #===========================================================================

    @staticmethod
    def initiate_transfer_service(sender_actor, data: dict):
        """Bước 1: Khởi tạo giao dịch PENDING và gửi OTP (Sử dụng Redis)"""
        receiver_account_num = data.get("receiver_account")
        amount = data.get("amount")
        description = data.get("description", "")

        if not receiver_account_num or not amount:
            raise ValueError("Thiếu thông tin người nhận hoặc số tiền.")

        amount = float(amount) # Nhớ đổi thành Decimal như góp ý ở trên nếu cần nhé
        if amount <= 0:
            raise ValueError("Số tiền chuyển phải lớn hơn 0.")

        sender_account = AccountBalance.query.filter_by(user_id=sender_actor.id).first()
        if not sender_account or not sender_account.can_transfer(amount):
            raise ValueError("Số dư không đủ hoặc tài khoản đang bị khóa.")

        receiver_account = AccountBalance.query.filter_by(account_number=receiver_account_num).first()
        if not receiver_account or sender_account.id == receiver_account.id:
            raise ValueError("Tài khoản người nhận không hợp lệ.")

        try:
            # 1. Tạo lịch sử giao dịch trạng thái PENDING
            tx_log = TransactionLog(
                sender_id=sender_actor.id,
                receiver_id=receiver_account.user_id,
                amount=amount,
                description=description,
                status="PENDING",
                requires_2fa=True, 
                two_fa_verified=False
            )
            db.session.add(tx_log)
            db.session.commit()

            # 2. Tạo mã OTP và lưu vào Redis (Thay cho DB)
            otp_code = UserService._generate_otp_code()
            hashed_otp = generate_password_hash(otp_code)
            key = f"otp:transfer:{sender_actor.id}"
            
            # Set thời gian sống (TTL) là 300s (5 phút)
            redis_client.setex(key, 300, hashed_otp)

            # 3. Gửi email OTP
            send_otp_email(sender_actor, otp_code)

            return tx_log

        except Exception as e:
            db.session.rollback()
            raise e


    @staticmethod
    def confirm_transfer_service(sender_actor, transaction_id, otp_code):
        """Bước 2: Xác thực OTP từ Redis và thực thi chuyển tiền"""
        
        # 1. Check OTP từ Redis
        key = f"otp:transfer:{sender_actor.id}"
        stored_hash = redis_client.get(key)

        if not stored_hash or not check_password_hash(stored_hash, otp_code):
            raise ValueError("Mã OTP không chính xác hoặc đã hết hạn.")

        # 2. Lấy giao dịch đang chờ
        tx = TransactionLog.query.filter_by(
            transaction_id=transaction_id, 
            sender_id=sender_actor.id, 
            status="PENDING"
        ).first()
        
        if not tx:
            raise ValueError("Không tìm thấy giao dịch hoặc giao dịch đã bị xử lý.")

        try:
            # 3. Khóa dòng dữ liệu (Chống double-spending)
            sender_account = AccountBalance.query.filter_by(user_id=sender_actor.id).with_for_update().first()
            receiver_account = AccountBalance.query.filter_by(user_id=tx.receiver_id).with_for_update().first()

            if not sender_account.can_transfer(tx.amount):
                tx.status = "FAILED"
                db.session.commit()
                raise ValueError("Số dư hiện tại không đủ để hoàn tất giao dịch.")

            # 4. Thực hiện biến động số dư
            tx.sender_balance_before = sender_account.balance
            tx.receiver_balance_before = receiver_account.balance

            sender_account.balance -= tx.amount
            receiver_account.balance += tx.amount

            tx.sender_balance_after = sender_account.balance
            tx.receiver_balance_after = receiver_account.balance
            
            # 5. Cập nhật trạng thái
            tx.status = "SUCCESS"
            tx.two_fa_verified = True
            
            db.session.commit()

            # 6. Hủy OTP trong Redis sau khi dùng xong (Xóa key)
            redis_client.delete(key)
            
            return tx

        except Exception as e:
            db.session.rollback()
            raise e


    @staticmethod
    def resend_transaction_otp_service(sender_actor, transaction_id):
        """Xử lý gửi lại OTP giao dịch (Lưu Redis)"""
        
        if not transaction_id:
            raise ValueError("Thiếu mã giao dịch.")

        tx = TransactionLog.query.filter_by(
            transaction_id=transaction_id, 
            sender_id=sender_actor.id, 
            status="PENDING"
        ).first()

        if not tx:
            raise ValueError("Không tìm thấy giao dịch hoặc giao dịch đã bị hủy.")

        try:
            # Ghi đè OTP mới vào Redis
            new_otp_code = UserService._generate_otp_code()
            hashed_otp = generate_password_hash(new_otp_code)
            key = f"otp:transfer:{sender_actor.id}"
            redis_client.setex(key, 300, hashed_otp)

            # Gửi lại email
            send_otp_email(sender_actor, new_otp_code)
            
            return True

        except Exception as e:
            # Xử lý lỗi hệ thống nếu có
            raise e