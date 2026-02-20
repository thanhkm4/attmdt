from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app.routes.dashboard_service import get_dashboard_data

main_bp = Blueprint("main", __name__)

@main_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    data = get_dashboard_data(current_user) # Hàm định nghĩa trong dashboard_service.py

    return render_template(
        "dashboard.html",
        role=current_user.role,
        **data
    )
