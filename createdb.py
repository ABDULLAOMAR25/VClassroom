from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib  # For password hashing

# --- Flask and DB setup ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///classes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Models ---
class ClassSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    is_live = db.Column(db.Boolean, default=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Store hashed password
    role = db.Column(db.String(10), nullable=False)
    reset_code = db.Column(db.String(100), nullable=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('class_session.id'), nullable=False)
    join_time = db.Column(db.DateTime, default=datetime.utcnow)
    leave_time = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref='attendances')
    session = db.relationship('ClassSession', backref='attendances')

# --- Password hashing helper ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- DB creation and sample data ---
with app.app_context():
    db.create_all()

    # Create sample users with hashed passwords
    user1 = User(username='teacher1', email='teacher1@example.com',
                 password=hash_password('pass123'), role='teacher')
    user2 = User(username='student1', email='student1@example.com',
                 password=hash_password('pass123'), role='student')
    admin_user = User(username='admin', email='admin@example.com',
                      password=hash_password('admin123'), role='admin')

    db.session.add_all([user1, user2, admin_user])
print("✅ Database 'classes.db' created with hashed passwords and admin user.")
