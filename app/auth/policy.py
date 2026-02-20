from app.models import User
from typing import Optional

# ===============================
# 1. CẤU HÌNH ROLE & QUYỀN
# ===============================
ROLE_LEVEL = {
    'admin': 100,       # Admin sàn Shopee
    'user': 50,   # Nhân viên shop
     # Người mua hàng
}


class PolicyResult:
    def __init__(self, ok: bool, reason: str = None, require_2fa: bool = False):
        self.ok = ok
        self.reason = reason
        self.require_2fa = require_2fa # Flag báo hiệu cần bật popup OTP

def allow(require_2fa=False):
    return PolicyResult(True, require_2fa=require_2fa)

def deny(reason: str):
    return PolicyResult(False, reason)

def check_user(actor: User, target_role: str, target_shop_id: Optional[int] = None):
    # Admin sàn có quyền làm mọi thứ
    if actor.role == 'admin':
        return allow()
    else: 
        return deny("Người đẹp không có quyền admin!")
