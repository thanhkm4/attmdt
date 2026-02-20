from app.models import User
from sqlalchemy.orm import joinedload

def get_dashboard_data(user):
    role = user.role

    # ================= ADMIN =================
    if role == "admin":
        return {
            
            "users": User.query.all()
        }

    
    return {
        "users": []
    }
