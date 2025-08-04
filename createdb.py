from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib  # For password hashing

# --- Flask and DB setup ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///classes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Prevent objects from expiring after commit so you can use them after session commit
db = SQLAlchemy(app, session_options={"expire_on_commit": False})

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

# --- Default users to initialize ---
defaults = [
    {"username": "Abdulla", "email": "mhatariabdulla@gmail.com", "password": "admin123", "role": "admin"},
    {"username": "Omar", "email": "teacher1@example.com", "password": "teacher123", "role": "teacher"},
    {"username": "student1", "email": "student1@example.com", "password": "student123", "role": "student"}
]

# --- Create tables and default users ---
with app.app_context():
    db.create_all()

    created_users = []
    for user_data in defaults:
        user = User.query.filter_by(email=user_data["email"]).first()
        if not user:
            user = User(
                username=user_data["username"],
                email=user_data["email"],
                password=hash_password(user_data["password"]),
                role=user_data["role"]
            )
            db.session.add(user)
            created_users.append(user)
    db.session.commit()

# Print users that were created (or loaded) - works because expire_on_commit=False
print("✅ Database initialized. Default users:")
for user in created_users:
    print(f"- {user.username} ({user.role})")
