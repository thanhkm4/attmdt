from flask import Blueprint, request, jsonify, url_for, render_template
from flask_login import login_required, current_user
from app.routes.user.user_services import UserService
from app.models import TransactionLog, AccountBalance, User
import traceback

user_bp = Blueprint("user", __name__, url_prefix="/users")

# ================================================================================================
# VIEW ROUTES (Trả về HTML)
# ================================================================================================

@user_bp.route("", methods=["GET"])
@login_required
def users_page():
    return render_template("config/user/list_search_user.html")

@user_bp.route("/<int:user_id>", methods=["GET"])
@login_required
def user_detail(user_id):
    # Nên check xem user_id có tồn tại không trước khi render (Optional)
    return render_template("user/create_user.html", user_id=user_id)

@user_bp.route("/profile", methods=["GET"])
@login_required
def profile_page():
    return render_template("dashboard.html")

@user_bp.route("/transfer", methods=["GET"])
@login_required
def transfer_page():
    return render_template("user/transaction.html")


# ================================================================================================
# API ROUTES (Trả về JSON)
# ================================================================================================

@user_bp.route("/create", methods=["POST"])
@login_required
def users_create():
    try:
        data = request.get_json()
        # [QUAN TRỌNG] Truyền current_user để Service check quyền can_create_user
        user = UserService.create_user_service(current_user, data)
        return jsonify({"success": True, "id": user.id}), 201

    except PermissionError as e:
        return jsonify({"success": False, "message": str(e)}), 403 # Trả về 403 nếu không có quyền
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400 # Trả về 400 nếu dữ liệu sai
    except Exception as e:
        print("LOG ERROR CREATE USER:")
        traceback.print_exc()
        return jsonify({"success": False, "message": "Lỗi hệ thống"}), 500

# ================================================================================================

@user_bp.route("/<int:user_id>", methods=["PUT"])
@login_required
def update_user(user_id):
    try:
        data = request.get_json()
        # [QUAN TRỌNG] Truyền current_user để check quyền update
        UserService.update_user_service(current_user, user_id, data)
        return jsonify({"success": True})
    
    except PermissionError as e:
        return jsonify({"success": False, "message": str(e)}), 403
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 400

# ================================================================================================

@user_bp.route("/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    try:
        # [QUAN TRỌNG] Truyền current_user để check quyền delete
        UserService.delete_user_service(current_user, user_id)
        return jsonify({"success": True})
    
    except PermissionError as e:
        return jsonify({"success": False, "message": str(e)}), 403
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

# ================================================================================================

@user_bp.route("/list", methods=["GET"])
@login_required
def list_users():
    # Phần filter giữ nguyên
    filters = {
        "keyword": request.args.get("keyword", ""),
        "role": request.args.get("role"),
        "is_active": request.args.get("is_active"),
        "page": int(request.args.get("page", 1)),
        "size": int(request.args.get("size", 20))
    }
    
    # [NÂNG CAO] Có thể truyền current_user vào để filter danh sách 
    # (Ví dụ: Station Manager chỉ nhìn thấy nhân viên của mình)
    return jsonify(UserService.list_users_service(current_user, filters))

# ================================================================================================

@user_bp.route("/meta", methods=["GET"])
@login_required  # <--- BỔ SUNG: Bảo vệ route này
def station_meta():
    # Lưu ý: Nếu làm Shopee Mini thì sửa lại Role ở đây hoặc lấy từ CONSTANT chung
    return jsonify({
        "role": [
            {"value": "admin", "label": "ADMIN"},
            {"value": "user", "label": "USER"}
        ],
        "unit": [] 
    })

# ================================================================================================

@user_bp.route('/<int:user_id>/unlock', methods=['POST'])
@login_required
def unlock_sub_user(user_id):
    try:
        # Gọi service
        UserService.unlock_created_user(current_user, user_id)
        return jsonify({"success": True, "message": "Mở khóa thành công"}), 200
        
    except PermissionError as e:
        return jsonify({"success": False, "message": str(e)}), 403
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

# ================================================================================================

@user_bp.route("/<int:user_id>/change-password", methods=["POST"])
@login_required
def change_password(user_id):
    try:
        data = request.get_json()
        UserService.change_password_service(user_id, data, current_user)
        return jsonify({
            "success": True, 
            "message": "Đổi mật khẩu thành công. Vui lòng đăng nhập lại."
        })
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 400
    except Exception as e:
        print(f"Change Password Error: {e}")
        return jsonify({"success": False, "message": "Lỗi hệ thống."}), 500
    

# ================================================================================================

@user_bp.route('/2fa/enable', methods=['POST'])
@login_required
def enable_2fa():
    data = request.json
    method = data.get('method', 'email') # 'email' hoặc 'sms'
    
    try:
        # Bước 1: Gửi OTP xác nhận trước khi bật (Optional nhưng nên làm)
        # Nếu logic của bạn đơn giản thì bật luôn:
        UserService.toggle_2fa_service(current_user, current_user.id, enable=True, method=method)
        return jsonify({"success": True, "message": "Đã bật xác thực 2 bước."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400
    
# ================================================================================================

@user_bp.route("/me", methods=["GET"])
@login_required
def get_my_profile():
    try:
        data = UserService.get_user_detail_service(current_user, current_user.id)
        return jsonify({"success": True, "data": data}), 200

    except PermissionError as e:
        return jsonify({"success": False, "message": str(e)}), 403
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Lỗi hệ thống"}), 500

# ================================================================================================

@user_bp.route("/me/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    try:
        file = request.files.get("avatar")
        result = UserService.upload_avatar_service(current_user, file)
        return jsonify({
            "success": True,
            "avatar": result
        })
    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 400
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Lỗi hệ thống"}), 500

# ================================================================================================

@user_bp.route('/transactions/create', methods=['POST'])
@login_required
def create_transaction_api():
    data = request.get_json(silent=True) or {}
    try:
        tx = UserService.initiate_transfer_service(current_user, data)
        # Thay vì báo thành công, trả về URL để frontend chuyển hướng sang trang nhập OTP
        return jsonify({
            "success": True, 
            "redirect": url_for("user.transfer_otp_page", tx_id=tx.transaction_id)
        }), 200
    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 400



@user_bp.route('/transactions/verify/<tx_id>', methods=['GET'])
@login_required
def transfer_otp_page(tx_id):
    """Render giao diện nhập OTP"""
    # Đảm bảo giao dịch này tồn tại và là của user hiện tại
    tx = TransactionLog.query.filter_by(transaction_id=tx_id, sender_id=current_user.id, status="PENDING").first_or_404()
    return render_template("user/transfer_otp.html", tx=tx)



@user_bp.route('/transactions/confirm', methods=['POST'])
@login_required
def confirm_transaction_api():
    data = request.get_json(silent=True) or {}
    tx_id = data.get("transaction_id")
    otp_code = data.get("otp")
    
    try:
        tx = UserService.confirm_transfer_service(current_user, tx_id, otp_code)
        return jsonify({
            "success": True, 
            "message": "Chuyển tiền thành công!",
            "redirect": url_for("user.profile_page") # Hoặc trang lịch sử GD
        }), 200
    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 400
    


@user_bp.route('/transactions/resend-otp', methods=['POST'])
@login_required
def resend_otp_transactions():
    data = request.get_json(silent=True) or {}
    transaction_id = data.get("transaction_id")
    
    try:
        # Gọi xuống tầng Service để xử lý
        UserService.resend_transaction_otp_service(current_user, transaction_id)
        
        return jsonify({
            "success": True, 
            "message": "Đã gửi lại mã OTP vào email của bạn."
        }), 200
        
    except ValueError as ve:
        return jsonify({
            "success": False, 
            "message": str(ve)
        }), 400
        
    except Exception as e:
        # app.logger.error(f"Lỗi gửi lại OTP giao dịch: {e}")
        return jsonify({
            "success": False, 
            "message": "Lỗi kết nối máy chủ, không thể gửi email lúc này."
        }), 500

# ================================================================================================

@user_bp.route('/api/check-account', methods=['GET'])
@login_required
def check_account_api():
    """API lấy thông tin người nhận khi gõ số tài khoản (Gọi bằng JS)"""
    account_number = request.args.get('account_number', '').strip()
    
    try:
        info = UserService.check_account_service(account_number)
        return jsonify({
            "success": True, 
            "full_name": info["full_name"],
            "username": info["username"]
        }), 200
        
    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 400
        
    except Exception as e:
        # app.logger.error(f"Check account error: {e}")
        return jsonify({"success": False, "message": "Lỗi máy chủ nội bộ."}), 500

