import logging
import json
import uuid
import sys
import os
import time
import traceback
from concurrent_log_handler import ConcurrentRotatingFileHandler
from flask import request, has_request_context, current_app, g, Response

from app.extensions import db
from app.models import AuditLog

# ==========================================
# 0. CẤU HÌNH CHUNG & MASKING HELPER
# ==========================================
# Danh sách các từ khóa nhạy cảm cần che
SENSITIVE_KEYS = {
    'password', 'token', 'access_token', 'refresh_token', 'repassword',
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
    """Format log thành JSON chuẩn, tự động lấy hết các trường trong extra"""
    
    # Các trường mặc định của LogRecord mà ta KHÔNG muốn đưa vào JSON output (để cho gọn)
    SKIP_ATTRS = {
        'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
        'funcName', 'levelname', 'levelno', 'lineno', 'module',
        'msecs', 'message', 'msg', 'name', 'pathname', 'process',
        'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName',
        'category' # Category đã xử lý riêng
    }

    def format(self, record):
        # 1. Các trường cơ bản bắt buộc
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "category": getattr(record, "category", "SYSTEM"),
            "message": record.getMessage(),
            "module": f"{record.module}:{record.lineno}",
        }
        
        # 2. Lấy Context Request (giữ nguyên logic cũ)
        if has_request_context():
            log_record["req_id"] = getattr(g, "request_id", "unknown")
            log_record["path"] = request.path
            log_record["method"] = request.method
            log_record["ip"] = request.headers.get("X-Forwarded-For", request.remote_addr)
            
            try:
                from flask_login import current_user
                if current_user.is_authenticated:
                    log_record["username"] = current_user.username
            except: pass

        # 3. [FIX QUAN TRỌNG] Tự động lấy các trường trong 'extra'
        # Khi bạn gọi logger.info(..., extra={'changes': {...}, 'body': {...}})
        # Python sẽ gán changes, body thành thuộc tính của record.
        # Ta duyệt qua record.__dict__, cái nào lạ (không nằm trong SKIP_ATTRS) thì đưa vào JSON.
        
        for key, value in record.__dict__.items():
            if key not in self.SKIP_ATTRS and key not in log_record:
                # Masking dữ liệu nhạy cảm trước khi ghi
                if isinstance(value, (dict, list)):
                    log_record[key] = mask_sensitive_data(value)
                else:
                    log_record[key] = value

        # 4. Xử lý Exception
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_record, ensure_ascii=False)
    
class HumanFormatter(logging.Formatter):
    """Format màu mè cho Console có kèm Context"""
    # 1. Định nghĩa các mã màu ANSI
    GREY, GREEN, YELLOW, RED, BOLD_RED, RESET = "\x1b[38;20m", "\x1b[32;20m", "\x1b[33;20m", "\x1b[31;20m", "\x1b[31;1m", "\x1b[0m"
    
    # [FIX] Thêm CYAN vào dòng này
    BLUE, MAGENTA, CYAN = "\x1b[34;20m", "\x1b[35;20m", "\x1b[36;20m" 
    
    # Format cơ bản
    FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

    def format(self, record):
        log_fmt = self.FORMAT
        
        # 1. Chọn màu theo Level
        if record.levelno == logging.DEBUG: prefix = self.GREY
        elif record.levelno == logging.INFO: prefix = self.GREEN
        elif record.levelno == logging.WARNING: prefix = self.YELLOW
        elif record.levelno == logging.ERROR: prefix = self.RED
        elif record.levelno == logging.CRITICAL: prefix = self.BOLD_RED
        else: prefix = self.RESET
        
        # 2. Xử lý Message chính
        formatter = logging.Formatter(f"{prefix}{log_fmt}{self.RESET}", datefmt="%Y-%m-%d %H:%M:%S")
        output = formatter.format(record)

        # 3. [QUAN TRỌNG] Bổ sung Context Data
        context_str = ""
        
        
        if hasattr(record, 'username'):
            context_str += f" | {self.MAGENTA}User:{record.username}{self.RESET}"
            
        if hasattr(record, 'ip'):
            context_str += f" | IP:{record.ip}"

        if hasattr(record, 'req_id'):
            # [SỬA 2] Rút gọn Request ID (lấy 8 ký tự đầu)
            short_req_id = str(record.req_id)[:8]
            context_str += f" | {self.GREY}ID:{short_req_id}{self.RESET}"

        # --- [HIỂN THỊ DIFF] ---
        if hasattr(record, 'changes') and record.changes:
            # Format JSON đẹp mắt, dùng màu CYAN (đã khai báo ở trên)
            changes_str = json.dumps(record.changes, ensure_ascii=False)
            context_str += f"\n   {self.CYAN}Diff: {changes_str}{self.RESET}"
        # -----------------------

        # Hiển thị Body (chỉ khi Warning/Error)
        if hasattr(record, 'body') and record.levelno >= logging.WARNING:
            context_str += f"\n   {self.GREY}Body: {json.dumps(record.body, ensure_ascii=False)}{self.RESET}"

        # Nguồn gốc file (Module)
        context_str += f" ({record.module}:{record.lineno})"

        output += context_str

        # 4. Xử lý Exception (Traceback)
        if record.exc_info:
            tb = traceback.format_exception(*record.exc_info)
            output += f"\n{self.RED}{''.join(tb)}{self.RESET}"
            
        return output
    
# ==========================================
# 2. SETUP LOGGING (Hàm khởi tạo)
# ==========================================
def setup_logging(app):
    del app.logger.handlers[:]
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
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
        
        file_handler = ConcurrentRotatingFileHandler(file_path, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        file_handler.setFormatter(JSONFormatter())
        file_handler.setLevel(logging.INFO)
        app.logger.setLevel(logging.INFO) 
        app.logger.addHandler(file_handler)
    
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
        elif duration > 5000: log_level = "WARNING" # Slow request > 10s

        message = f"{request.method} {request.path} - {status_code} - {duration}ms"
        
        # Gọi hàm log_system nội bộ
        log_system(log_level, message, category="REQUEST", extra=extra_data)

        # Trả Request ID về header cho Client debug
        response.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return response

# ==========================================
# 4. HELPER FUNCTIONS (System & Audit)
# ==========================================
def log_system(level: str, message: str, category: str = "SYSTEM", extra: dict = None, stack_level: int = 2):
    """Wrapper để ghi log hệ thống (File/Console)"""
    
    # 1. Đảm bảo extra luôn là dictionary
    if extra is None: extra = {}
    
    # 2. [THÊM MỚI] Tự động chèn User, IP, Request ID nếu chưa có
    if has_request_context():
        # Tự lấy IP nếu chưa truyền
        if "ip" not in extra:
            extra["ip"] = request.headers.get("X-Forwarded-For", request.remote_addr)
            
        # Tự lấy Request ID nếu chưa truyền
        if "req_id" not in extra:
            extra["req_id"] = getattr(g, "request_id", "unknown")

        # Tự lấy Username nếu chưa truyền
        if "username" not in extra:
            try:
                from flask_login import current_user
                if current_user.is_authenticated:
                    extra["username"] = f"{current_user.username} ({current_user.id})"
            except: 
                pass

    # 3. Ghi log như cũ
    lvl = level.upper()
    logger_func = getattr(current_app.logger, lvl.lower(), current_app.logger.info)
    
    extra_payload = extra.copy()
    extra_payload['category'] = category
    
    logger_func(message, extra=extra_payload, stacklevel=stack_level)
    

def log_audit(action: str, category: str, target_model=None, changes: dict = None, description: str = None):
    """Ghi Audit Log vào Database"""
    try:
        from flask_login import current_user 
        from flask import g# Import lười để tránh circular import
        user_id = None
        if current_user and current_user.is_authenticated:
            user_id = current_user.id
            username = current_user.username
        ip = request.remote_addr if has_request_context() else "SYSTEM"
        req_id = getattr(g, "request_id", "unknown") if has_request_context() else "system"
        
        target_type = target_model.__class__.__name__ if target_model else None
        target_id = getattr(target_model, 'id', None) if target_model else None

        # Masking changes trước khi lưu DB (Tùy chọn, ở đây ta lưu raw nhưng password đã xử lý ở Service)
        # Nếu muốn chắc ăn, có thể mask ở đây luôn:
        if changes:
            changes = mask_sensitive_data(changes)

        audit_entry = AuditLog(
            user_id=user_id,
            username=username,
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
        log_msg = f"AUDIT: {action} {target_type or ''} - {description}"
        log_system("INFO", log_msg, category="AUDIT", extra={
            # --- QUAN TRỌNG: Truyền đúng key mà HumanFormatter mong đợi ---
            "username": f"{username} ({user_id})", # Để hiện "User:..." màu tím
            "ip": ip,                       # Để hiện "IP:..."
            "req_id": req_id,               # Để hiện "ID:..." màu xám
            # -------------------------------------------------------------
            "action": action, 
            "target_id": target_id, 
            "changes": changes
        }, stack_level=3)
    except Exception as e:
        # Fallback ra file log nếu DB lỗi
        fallback = {
            "type": "AUDIT_FAIL", "action": action, "error": str(e), 
            "changes": mask_sensitive_data(changes)
        }
        current_app.logger.error(f"AUDIT_LOG_FALLBACK: {json.dumps(fallback)}")