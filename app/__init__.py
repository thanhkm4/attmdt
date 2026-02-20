from flask import Flask
from config import Config
from .extensions import db, migrate, login_manager
# Import models để DB nhận diện
from app.models import User
from app.menu_config import MENU
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from .extensions import mail

csrf = CSRFProtect()

def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )
    app.config.from_object(Config)
    # --- PHẦN BẠN ĐANG THIẾU ---
    # Phải khởi tạo các extension với app thì mới chạy lệnh db được
    db.init_app(app)
    migrate.init_app(app, db) # Quan trọng: Phải có dòng này mới chạy được flask db
    login_manager.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    # ---------------------------
    # Đăng ký route login (kéo từ chỗ khác về và tập trung ở đây)
    from app.auth.login_routes import auth_bp
    app.register_blueprint(auth_bp)

    # Đăng ký route /
    from app.routes.main import main_bp
    app.register_blueprint(main_bp)

    # Đăng ký logging
    from app.logs.logs_app import setup_logging, register_request_logger
    setup_logging(app)
    register_request_logger(app)

    # Đăng ký error handlers
    from app.errors.handlers import register_error_handlers
    register_error_handlers(app)
    
    # Đăng ký route chức năng quản lý người dùng
    from app.routes.user.user_routes import user_bp
    app.register_blueprint(user_bp)
    

    # Inject menu vào tất cả các template    
    @app.context_processor
    def inject_menu():
        return {
            "menu": MENU
        }
        
    return app

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

