from flask import Blueprint, request, render_template, flash, redirect, url_for, jsonify, session
from flask_login import logout_user, login_required, current_user, login_user
from app.extensions import db
from app.auth.mail_service import send_verification_email
# Import Services
import hashlib
from app.models import EmailVerificationToken, User
from app.routes.user.user_services import UserService
from app.auth.auth_service import AuthService
auth_service = AuthService()
auth_bp = Blueprint("auth", __name__)

# =========================================================================
@auth_bp.route("/otp-login", methods=["GET"])
def otp_login_page():
    if not session.get("pre_2fa_user_id"):
        flash("Phiên xác thực không hợp lệ.", "danger")
        return redirect(url_for("auth.login"))

    return render_template("auth.html")
# =========================================================================
# =========================================================================
@auth_bp.route('/api/check-session', methods=['GET'])
def check_session_status():
    session.modified = False
    if current_user.is_authenticated:
        return jsonify({"status": "active"}), 200
    else:
        return jsonify({"status": "expired"}), 401
# =========================================================================
# =========================================================================
@auth_bp.route("/send-login-otp", methods=["POST"])
def send_login_otp():
    try:
        user_id = session.get("pre_2fa_user_id")
        if not user_id:
            return jsonify({"error": "Phiên không hợp lệ"}), 401
        AuthService.request_otp(user_id, purpose="login")
        return jsonify({"message": "OTP đã được gửi lại"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@auth_bp.route("/send-enable-2fa-otp", methods=["POST"])
@login_required
def send_enable_2fa_otp():
    AuthService.request_otp(current_user.id, purpose="enable_2fa")
    return jsonify({"message": "OTP xác nhận đã được gửi"})
# =========================================================================
# =========================================================================
@auth_bp.route("/verify-otp", methods=["POST"])
@login_required
def verify_otp():
    otp_code = request.json.get("otp")

    if not otp_code:
        return jsonify({"error": "Thiếu OTP"}), 400

    try:
        # Gọi service verify
        is_valid = AuthService.verify_otp_service(current_user.id, otp_code)

        if not is_valid:
            return jsonify({"error": "OTP sai hoặc hết hạn"}), 400

        # Nếu đúng → bật 2FA
        AuthService.toggle_2fa_service(
            actor=current_user,
            user_id=current_user.id,
            enable=True,
            method="email"
        )

        return jsonify({"message": "Kích hoạt 2FA thành công"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# =========================================================================
# =========================================================================
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect(url_for("main.index"))
        return render_template("login.html")

    data = request.get_json(silent=True) or request.form
    username = data.get("username")
    password = data.get("password")

    result = auth_service.login(
        username=username,
        password=password,
        ip_address=request.remote_addr
    )

    # ❌ LOGIN FAIL
    if not result.success:
        if request.is_json:
            return jsonify({"success": False, "message": result.message}), 401
        flash(result.message, "danger")
        return render_template("login.html"), 401

    # ✅ LOGIN SUCCESS

    # Nếu có 2FA
    if isinstance(result.message, dict) and "pre_2fa_user_id" in result.message:
        session.update(result.message)

        if request.is_json:
            return jsonify({
                "success": True,
                "redirect": url_for(result.redirect_to)
            })

        return redirect(url_for(result.redirect_to))

    # Login thường
    if isinstance(result.message, dict) and "login_log_id" in result.message:
        session["login_log_id"] = result.message["login_log_id"]

    if request.is_json:
        return jsonify({
            "success": True,
            "redirect": url_for(result.redirect_to)
        })

    return redirect(url_for(result.redirect_to))
# =========================================================================
# =========================================================================
@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect(url_for("main.index"))
        return render_template("register.html")

    data = request.get_json(silent=True) or request.form

    try:
        user = UserService.register_user_service(data)
        session["pending_verify_email"] = user.email
        # gửi email verify
        token = EmailVerificationToken.generate_email_verification_token(user)
        send_verification_email(user, token)

        if request.is_json:
            return jsonify({
                "success": True,
                "redirect": url_for("auth.verify_notice")
            })

        flash("Đăng ký thành công. Vui lòng kiểm tra email để xác thực.", "success")
        return redirect(url_for("auth.verify_notice"))

    except ValueError as ve:
        if request.is_json:
            return jsonify({"success": False, "message": str(ve)}), 400

        flash(str(ve), "danger")
        return redirect(url_for("auth.verify_notice")), 400

    except Exception as ex:
        if request.is_json:
            return jsonify({"success": False, "message": str(ex) }), 500

        flash(str(ex), "danger")
        return redirect(url_for("auth.verify_notice")), 500
# =========================================================================
# =========================================================================
@auth_bp.route("/resend-verification", methods=["POST"])
def resend_verification():

    email = session.get("pending_verify_email")

    if not email:
        flash("Phiên xác thực không hợp lệ.", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Người dùng không tồn tại.", "danger")
        return redirect(url_for("auth.login"))

    if user.email_verified:
        flash("Email đã được xác thực.", "info")
        return redirect(url_for("auth.login"))

    try:
        token = EmailVerificationToken.generate_email_verification_token(user)
        send_verification_email(user, token)

        flash("Email xác thực đã được gửi lại.", "success")

    except Exception as e:
        flash(f"Lỗi khi gửi email: {str(e)}", "danger")

    return redirect(url_for("auth.verify_notice"))
# =========================================================================
# =========================================================================
@auth_bp.route("/verify-notice")
def verify_notice():
    email = session.get("pending_verify_email")
    if not email:
        return redirect(url_for("auth.login"))

    return render_template("verify_pending.html", email=email)


# =========================================================================
# =========================================================================    
@auth_bp.route('/verify-otp-login', methods=['POST'])
def verify_otp_login():
    user_id = session.get("pre_2fa_user_id")
    login_log_id = session.get("pre_2fa_log_id")

    if not user_id:
        return jsonify({"success": False, "message": "Hết phiên đăng nhập"}), 401

    otp_code = request.json.get("otp")

    success, error = auth_service.verify_login_otp_service(
        user_id,
        otp_code,
        login_log_id
    )

    if not success:

        # Nếu bị lock OTP
        if error == "LOCKED_OTP":
            session.pop("pre_2fa_user_id", None)
            session.pop("pre_2fa_log_id", None)

            return jsonify({
                "success": False,
                "redirect": url_for("auth.login"),
                "message": "Bạn đã nhập sai OTP quá nhiều lần. Vui lòng đăng nhập lại."
            }), 401

        return jsonify({"success": False, "message": error}), 400


    session["login_log_id"] = login_log_id
    session.pop("pre_2fa_user_id", None)
    session.pop("pre_2fa_log_id", None)

    return jsonify({
        "success": True,
        "redirect": url_for("main.index")
    })
# =========================================================================
# =========================================================================
@auth_bp.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    user = current_user
    user.two_factor_method = None
    db.session.commit()
    return jsonify({"success": True, "message": "Đã tắt 2FA"})
# =========================================================================
# =========================================================================
@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    user = AuthService.verify_email_token(token)
    print("TOKEN TỪ URL:", token)
    print("HASH:", hashlib.sha256(token.encode()).hexdigest())

    if not user:
        flash("Link không hợp lệ hoặc đã hết hạn.", "danger")
        return redirect(url_for("auth.login"))

    flash("Xác thực thành công!", "success")
    return redirect(url_for("auth.login"))

# =========================================================================
# =========================================================================
@auth_bp.route("/logout")
@login_required
def logout():
    login_log_id = session.get('login_log_id')
    if login_log_id:
        AuthService().logout(login_log_id)
        session.pop('login_log_id', None)
    logout_user()
    return redirect(url_for("auth.login"))
