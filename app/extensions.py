from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime, timezone, timedelta
from flask_mail import Mail
import redis
import os
from dotenv import load_dotenv

# 1. Cấu hình Login Manager
login_manager = LoginManager()
login_manager.login_view = "auth.login" # pyright: ignore[reportAttributeAccessIssue]
login_manager.login_message = "Vui lòng đăng nhập để truy cập."

# 2. Cấu hình SQLAlchemy và Migrate
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
load_dotenv()
redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL"),
    decode_responses=True  # để trả về string thay vì bytes
)

# 3. Hàm lấy thời gian Việt Nam
def get_vietnam_time():
    """Lấy thời gian hiện tại theo múi giờ Việt Nam (UTC+7)"""
    utc_now = datetime.now(timezone.utc)
    vietnam_tz = timezone(timedelta(hours=7))
    return utc_now.astimezone(vietnam_tz).replace(tzinfo=None)

