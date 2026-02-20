from flask import render_template, jsonify, request, current_app
from werkzeug.exceptions import HTTPException
import traceback

# Import Logger mới
from app.logs.logs_app import log_system

def register_error_handlers(app):

    def _get_error_info(e):
        """Helper lấy mã lỗi và nội dung"""
        code = 500
        description = "Internal Server Error"
        
        if isinstance(e, HTTPException):
            code = e.code
            description = e.description
        
        return code, description

    def _render_error(e):
        """
        Hàm xử lý chung cho mọi lỗi HTTP (4xx).
        Tự động trả về JSON hoặc HTML tùy theo người gọi.
        """
        code, description = _get_error_info(e)

        # 1. LOGGING
        # Lỗi 4xx chỉ là WARNING (do người dùng), Lỗi 5xx mới là ERROR (do hệ thống)
        log_level = "ERROR" if code >= 500 else "WARNING"
        
        log_system(log_level, f"HTTP Error {code}", extra={
            "url": request.path,
            "method": request.method,
            "description": description
        })

        # 2. CONTENT NEGOTIATION (Trả về JSON hay HTML?)
        # Nếu request muốn JSON HOẶC đường dẫn bắt đầu bằng /api/
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": {
                    "code": code,
                    "type": e.__class__.__name__,
                    "message": description
                }
            }), code

        # 3. HTML FALLBACK
        # Nếu không có template riêng (vd 418.html), dùng template mặc định 500 hoặc 404
        # Ở đây giữ logic của bạn: Render file theo mã lỗi
        try:
            return render_template(f"errors/{code}.html", error_code=code, message=description), code
        except:
            # Nếu chưa tạo file 4xx.html thì trả về file error chung
            return render_template("errors/generic.html", error_code=code, message=description), code

    # =================================================
    # ĐĂNG KÝ CÁC MÃ LỖI THÔNG DỤNG (400 -> 429)
    # =================================================
    for code in [400, 401, 403, 404, 405, 429]:
        app.register_error_handler(code, _render_error)

    # =================================================
    # XỬ LÝ RIÊNG CHO LỖI 500 & UNHANDLED EXCEPTION
    # =================================================
    @app.errorhandler(Exception)
    def handle_exception(e):
        """
        Bắt tất cả các lỗi crash code (Bug) mà không phải HTTPException
        """
        # Nếu là HTTPException (vd 404 do thư viện khác raise) -> Chuyển về handler trên
        if isinstance(e, HTTPException):
            return _render_error(e)

        # Đây là lỗi Crash thực sự (Code sai, DB chết,...) -> Cần Log Traceback
        tb = traceback.format_exc()
        log_system("ERROR", "Unhandled Exception (Crash)", extra={
            "error": str(e),
            "url": request.url,
            "traceback": tb # Quan trọng để debug
        })

        # Trả về response
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "message": "Lỗi hệ thống nội bộ. Vui lòng liên hệ Admin.",
                "debug_error": str(e) if current_app.debug else None # Chỉ hiện lỗi chi tiết khi Debug=True
            }), 500

        return render_template("errors/500.html", error=str(e) if current_app.debug else None), 500