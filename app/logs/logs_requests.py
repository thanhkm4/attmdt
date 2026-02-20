import logging
import json
import uuid
import sys
import os
import time
import traceback
from logging.handlers import RotatingFileHandler
from flask import request, has_request_context, current_app, g, Response

from apps.extensions import db
from apps.models import AuditLog

# ==========================================
# 0. CẤU HÌNH CHUNG & MASKING HELPER
# ==========================================
# Danh sách các từ khóa nhạy cảm cần che
SENSITIVE_KEYS = {
    'password', 'token', 'access_token', 'refresh_token', 
    'otp', 'api_key', 'secret', 'authorization', 'card_number'
}

def mask_sensitive_data(data):
    """
    Hàm đệ quy dùng chung để che giấu thông tin nhạy cảm 
    trong dict/list bất kỳ (Body request, Log record, v.v.)
    """
    if isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            if k.lower() in SENSITIVE_KEYS:
                new_data[k] = "***MASKED***"
            else:
                new_data[k] = mask_sensitive_data(v)
        return new_data
    elif isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data

# ==========================================
# 1. FORMATTER (JSON & HUMAN)
# ==========================================
class JSONFormatter(logging.Formatter):
    """Format log thành JSON chuẩn cho File/Splunk/ELK"""
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": f"{record.module}:{record.lineno}",
        }
        
        # Lấy Context nếu có
        if has_request_context():
            log_record["req_id"] = getattr(g, "request_id", "unknown")
            log_record["path"] = request.path
            log_record["method"] = request.method
            log_record["ip"] = request.headers.get("X-Forwarded-For", request.remote_addr)
            
            # User ID (nếu đã login)
            # Lưu ý: Import User ở đây hoặc check current_user an toàn
            try:
                from flask_login import current_user
                if current_user.is_authenticated:
                    log_record["user_id"] = current_user.id
            except: pass

        # TỰ ĐỘNG CHE DỮ LIỆU NHẠY CẢM TRONG 'EXTRA' HOẶC 'MESSAGE'
        if hasattr(record, 'args') and isinstance(record.args, dict):
             record.args = mask_sensitive_data(record.args)
             
        # Parse message nếu nó là dict (đề phòng dev log thẳng object)
        try:
            if isinstance(record.msg, dict):
                 record.msg = mask_sensitive_data(record.msg)
        except: pass

        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_record, ensure_ascii=False)

class HumanFormatter(logging.Formatter):
    """Format màu mè cho Console"""
    GREY, GREEN, YELLOW, RED, BOLD_RED, RESET = "\x1b[38;20m", "\x1b[32;20m", "\x1b[33;20m", "\x1b[31;20m", "\x1b[31;1m", "\x1b[0m"
    FORMAT = "%(asctime)s - %(levelname)s - %(message)s (%(module)s:%(lineno)d)"

    def format(self, record):
        log_fmt = self.FORMAT
        if record.levelno == logging.DEBUG: prefix = self.GREY
        elif record.levelno == logging.INFO: prefix = self.GREEN
        elif record.levelno == logging.WARNING: prefix = self.YELLOW
        elif record.levelno == logging.ERROR: prefix = self.RED
        elif record.levelno == logging.CRITICAL: prefix = self.BOLD_RED
        else: prefix = self.RESET
        
        formatter = logging.Formatter(f"{prefix}{log_fmt}{self.RESET}")
        output = formatter.format(record)
        if record.exc_info:
            tb = traceback.format_exception(*record.exc_info)
            output += f"\n{self.RED}{''.join(tb)}{self.RESET}"
        return output

# ==========================================
# 2. SETUP LOGGING (Hàm khởi tạo)
# ==========================================
def setup_logging(app):
    del app.logger.handlers[:]
    
    # KÊNH 1: CONSOLE
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(HumanFormatter())
    console_handler.setLevel(logging.DEBUG if app.debug else logging.INFO)
    app.logger.addHandler(console_handler)

    # KÊNH 2: FILE
    log_folder = app.config.get("LOG_FOLDER", "logs")
    log_file_name = app.config.get("LOG_FILE", "app.json.log")
    
    if log_folder:
        if not os.path.exists(log_folder): os.makedirs(log_folder)
        file_path = os.path.join(log_folder, log_file_name)
        
        file_handler = RotatingFileHandler(file_path, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        file_handler.setFormatter(JSONFormatter())
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

    # Ép Werkzeug dùng chung handler
    logging.getLogger('werkzeug').handlers = []
    logging.getLogger('werkzeug').addHandler(console_handler)
    if log_folder: logging.getLogger('werkzeug').addHandler(file_handler)
    
    print(f" -> Logging setup complete: Console + File ({log_file_name})")

# ==========================================
# 3. REQUEST LOGGING MIDDLEWARE (Tích hợp vào đây)
# ==========================================
def register_request_logger(app):
    """
    Đăng ký middleware để đo thời gian và log toàn bộ request HTTP.
    Gọi hàm này trong create_app() hoặc app.py.
    """
    
    @app.before_request
    def start_timer():
        # 1. Đánh dấu thời gian & Tạo Request ID
        g.start_time = time.time()
        g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

    @app.after_request
    def log_request(response: Response):
        # Không log file tĩnh hoặc OPTIONS
        if request.path.startswith("/static") or request.method == "OPTIONS":
            return response

        # Tính toán Duration
        start = getattr(g, "start_time", None)
        if start:
            duration = round((time.time() - start) * 1000, 2)
        else:
            duration = 0 # Fallback nếu crash quá sớm

        status_code = response.status_code
        
        # Lấy Body (Masked)
        body_log = None
        if request.is_json:
            try:
                # Chỉ log body nhỏ < 2KB
                if request.content_length and request.content_length < 2048:
                    # Dùng chung hàm mask_sensitive_data đã định nghĩa ở trên
                    body_log = mask_sensitive_data(request.get_json(silent=True))
            except: pass

        # Chuẩn bị Extra Data
        extra_data = {
            "req_id": getattr(g, "request_id", "unknown"),
            "status": status_code,
            "duration_ms": duration,
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            "query": request.query_string.decode() if request.query_string else None
        }
        if body_log and request.method != "GET":
            extra_data["body"] = body_log

        # Quyết định Level & Message
        log_level = "INFO"
        if status_code >= 500: log_level = "ERROR"
        elif status_code >= 400: log_level = "WARNING"
        elif duration > 1000: log_level = "WARNING" # Slow request > 1s

        message = f"{request.method} {request.path} - {status_code} - {duration}ms"
        
        # Gọi hàm log_system nội bộ
        log_system(log_level, message, extra=extra_data)

        # Trả Request ID về header cho Client debug
        response.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return response

# ==========================================
# 4. HELPER FUNCTIONS (System & Audit)
# ==========================================
def log_system(level: str, message: str, extra: dict = None):
    """Wrapper để ghi log hệ thống (File/Console)"""
    # Nếu có extra, JSONFormatter sẽ tự động mask, HumanFormatter sẽ in ra
    msg_content = message
    # Với HumanFormatter (Console), ta nối chuỗi để dễ đọc
    # Với JSONFormatter (File), nó sẽ xử lý riêng record.args
    
    lvl = level.upper()
    logger_func = getattr(current_app.logger, lvl.lower(), current_app.logger.info)
    
    # Truyền extra vào kwargs 'extra' không hoạt động tốt với mọi formatter
    # Cách tốt nhất là truyền dict vào tham số, JSONFormatter sẽ bắt lấy
    if extra:
        logger_func(message, extra) # Truyền extra data vào args của record
    else:
        logger_func(message)

def log_audit(action: str, category: str, target_model=None, changes: dict = None, description: str = None):
    """Ghi Audit Log vào Database"""
    try:
        from flask_login import current_user # Import lười để tránh circular import
        user_id = current_user.id if current_user and current_user.is_authenticated else None
        ip = request.remote_addr if has_request_context() else "SYSTEM"
        
        target_type = target_model.__class__.__name__ if target_model else None
        target_id = getattr(target_model, 'id', None) if target_model else None

        # Masking changes trước khi lưu DB (Tùy chọn, ở đây ta lưu raw nhưng password đã xử lý ở Service)
        # Nếu muốn chắc ăn, có thể mask ở đây luôn:
        if changes:
            changes = mask_sensitive_data(changes)

        audit_entry = AuditLog(
            user_id=user_id,
            ip_address=ip,
            category=category,
            action=action,
            target_type=target_type,
            target_id=target_id,
            changes=changes,
            description=description
        )
        db.session.add(audit_entry)
        # Lưu ý: Không commit ở đây
    except Exception as e:
        # Fallback ra file log nếu DB lỗi
        fallback = {
            "type": "AUDIT_FAIL", "action": action, "error": str(e), 
            "changes": mask_sensitive_data(changes)
        }
        current_app.logger.error(f"AUDIT_LOG_FALLBACK: {json.dumps(fallback)}")