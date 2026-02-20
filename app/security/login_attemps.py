from app.models import FailedLoginAttempt, get_vietnam_time
from app.extensions import db
from flask import current_app, request
from sqlalchemy import or_
from datetime import timedelta

def get_failed_attempt_count(username, ip_address):
    # 1. Dọn dẹp log cũ (giữ nguyên logic của bạn)
    ten_minutes_ago = get_vietnam_time() - timedelta(minutes=10)
    # Lưu ý: Việc delete này nên để ở một cronjob riêng nếu hệ thống lớn, 
    # nhưng để ở đây cũng được nếu ít user.
    FailedLoginAttempt.query.filter(FailedLoginAttempt.attempt_time < ten_minutes_ago).delete()
    db.session.commit()
    
    # 2. Đếm số lần sai (SỬA: Chỉ đếm theo Username)
    recent_failures = FailedLoginAttempt.query.filter(
            # --- ĐOẠN ĐÃ SỬA: Bỏ db.or_ và bỏ check IP ---
            FailedLoginAttempt.username == username, 
            # ---------------------------------------------
            FailedLoginAttempt.attempt_time >= ten_minutes_ago
        ).count()
    
    return recent_failures

def is_account_locked(username, ip):
    return get_failed_attempt_count(username, ip) >= current_app.config["MAX_LOGIN_ATTEMPTS"]


def record_failed_attempt(username, ip):
    # Lấy User Agent (ví dụ: Mozilla/5.0...)
    ua = request.headers.get('User-Agent', '')[:255] 
    
    attempt = FailedLoginAttempt(
        username=username,
        ip_address=ip,
        user_agent=ua, # Lưu thêm cái này
        attempt_time=get_vietnam_time()
    )            
    db.session.add(attempt)
    db.session.commit()               # thêm vào database
 
    

def clear_failed_attempts(username, ip):
    # SỬA: Chỉ xóa log của chính username đó khi họ đăng nhập thành công.
    # Không xóa theo IP, vì IP đó có thể chứa log thất bại của user khác.
    FailedLoginAttempt.query.filter(
        FailedLoginAttempt.username == username
    ).delete()
    
    db.session.commit()
    
    
def reset_user_lock(username):
    """
    Hàm này dùng để Admin mở khóa nóng cho user, 
    hoặc dùng khi test để đỡ phải chờ hết thời gian khóa.
    """
    FailedLoginAttempt.query.filter_by(username=username).delete()
    db.session.commit()
    return True