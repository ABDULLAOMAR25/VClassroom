from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
import jwt
import time
from datetime import datetime
from dotenv import load_dotenv
import os
import zipfile
import csv
from io import StringIO
from werkzeug.utils import secure_filename
from pathlib import Path

# Load environment variables
load_dotenv(dotenv_path=Path('.') / '.env')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key')

API_KEY = os.getenv("LIVEKIT_API_KEY")
API_SECRET = os.getenv("LIVEKIT_API_SECRET")
LIVEKIT_URL = os.getenv("LIVEKIT_URL")
LIVEKIT_EGRESS_URL = os.getenv("LIVEKIT_EGRESS_URL")

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_VIDEO = {'mp4', 'mkv', 'avi'}
ALLOWED_NOTES = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt'}

db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///classes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

# Models
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
    password = db.Column(db.String(100), nullable=False)
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

# Helpers
def allowed_file(filename, allowed_ext):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_ext

# Routes

@app.route('/')
def index():
    return "✅ VClassroom Flask App is running!"

@app.route('/init-db')
def init_db():
    db.create_all()
    return "✅ Database initialized!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    next_page = request.args.get('next')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            session['role'] = user.role
            flash(f"Logged in successfully as {user.role.capitalize()}")
            return redirect(next_page or url_for(f"{user.role}_dashboard"))
        flash("Invalid username or password")
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('login'))

@app.route('/dashboard_student')
def student_dashboard():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    return render_template('dashboard_student.html')

@app.route('/dashboard_teacher')
def teacher_dashboard():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    return render_template('dashboard_teacher.html')

@app.route('/dashboard_admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    return render_template('dashboard_admin.html')

@app.route('/admin/manage-users', methods=['GET', 'POST'])
def manage_users():
    if session.get('role') != 'admin':
        flash("Access denied. Admins only.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if request.form.get('action') == 'add_user':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')

            if not all([username, email, password, role]):
                flash("⚠️ All fields are required to add a user.")
            else:
                existing_user = User.query.filter(or_(User.username == username, User.email == email)).first()
                if existing_user:
                    flash("⚠️ Username or email already exists.")
                else:
                    new_user = User(username=username, email=email, password=password, role=role)
                    db.session.add(new_user)
                    db.session.commit()
                    flash(f"✅ New {role} user '{username}' added.")

        elif request.form.get('delete_user_id'):
            user_id = request.form.get('delete_user_id')
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash(f"🗑️ User '{user.username}' deleted successfully.")
            else:
                flash("⚠️ User not found.")

        return redirect(url_for('manage_users'))

    role_filter = request.args.get('role')
    if role_filter in ['admin', 'teacher', 'student']:
        users = User.query.filter_by(role=role_filter).order_by(User.id).all()
    else:
        users = User.query.order_by(User.id).all()

    return render_template('manage_users.html', users=users, role_filter=role_filter)

@app.route('/add-default-users')
def add_default_users():
    messages = []

    if not User.query.filter_by(username="Abdulla").first():
        admin = User(username="Abdulla", email="mhatariabdulla@gmail.com", password="admin123", role="admin")
        db.session.add(admin)
        messages.append("✅ Admin user created.")
    else:
        messages.append("⚠️ Admin user already exists.")

    if not User.query.filter_by(username="Omar").first():
        teacher = User(username="Omar", email="teacher1@example.com", password="teacher123", role="teacher")
        db.session.add(teacher)
        messages.append("✅ Teacher user created.")
    else:
        messages.append("⚠️ Teacher user already exists.")

    if not User.query.filter_by(username="student1").first():
        student = User(username="student1", email="student1@example.com", password="student123", role="student")
        db.session.add(student)
        messages.append("✅ Student user created.")
    else:
        messages.append("⚠️ Student user already exists.")

    db.session.commit()
    return "<br>".join(messages)

# You can add your other routes here like session handling, LiveKit token, uploads, etc.

if __name__ == '__main__':
    app.run(debug=True)
