from app import create_app
from app.extensions import db
from app.models import User 
app = create_app()

with app.app_context():
    username = "admin"
    password = "123"
    email = "admin@attmdt.system"

    admin_user = User(username=username, email=email, role="admin")
    admin_user.set_password(password)
    db.session.add(admin_user)
    db.session.commit()