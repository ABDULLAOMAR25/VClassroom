from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
import jwt
from flask_cors import CORS
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
from livekit import api
import os
import zipfile
import csv
from io import StringIO
from werkzeug.utils import secure_filename
from sqlalchemy import text
from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler
import hashlib
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
import sys

# --- Load environment variables ---
load_dotenv(dotenv_path=Path('.') / '.env')

# --- Flask App Setup ---
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = "your_generated_secret_key_here"

# --- Logging Setup ---
if not os.path.exists('logs'):
    os.mkdir('logs')
log_formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=100000, backupCount=3)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.addHandler(stream_handler)
app.logger.setLevel(logging.INFO)

# --- LiveKit Config ---
API_KEY = os.getenv("LIVEKIT_API_KEY")
API_SECRET = os.getenv("LIVEKIT_API_SECRET")
LIVEKIT_URL = os.getenv("LIVEKIT_URL")

# --- File Upload Config ---
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_VIDEO = {'mp4', 'mkv', 'avi'}
ALLOWED_NOTES = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt'}

# --- Database Config ---
db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///classes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    reset_code = db.Column(db.String(100), nullable=True)
    sessions = db.relationship('ClassSession', backref='teacher', lazy=True)

class ClassSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    topic = db.Column(db.String(200))
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_live = db.Column(db.Boolean, default=False)

    @property
    def status(self):
        now = datetime.utcnow()
        if not self.start_time:
            return 'Not Started'
        elif self.start_time > now:
            return 'Not Started'
        elif self.end_time and self.end_time <= now:
            return 'Ended'
        else:
            return 'Live'

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('class_session.id'), nullable=False)
    join_time = db.Column(db.DateTime, default=datetime.utcnow)
    leave_time = db.Column(db.DateTime, nullable=True)
    user = db.relationship('User', backref='attendances')
    session = db.relationship('ClassSession', backref='attendances')

# --- Helper ---
def allowed_file(filename, allowed_ext):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_ext

# --- Routes ---
@app.route('/')
def index():
    return "✅ VClassroom Flask App is running!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    next_page = request.args.get('next')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.password == hash_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            flash(f"✅ Logged in successfully as {user.role.capitalize()}")
            return redirect(next_page or url_for(f"{user.role}_dashboard"))

        flash("❌ Invalid username or password")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('login'))

@app.route('/dashboard_student')
def student_dashboard():
    if session.get('role') != 'student': return redirect(url_for('login'))
    return render_template('dashboard_student.html')

@app.route('/dashboard_teacher')
def teacher_dashboard():
    if session.get('role') != 'teacher': return redirect(url_for('login'))
    return render_template('dashboard_teacher.html')

@app.route('/dashboard_admin')
def admin_dashboard():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    return render_template('dashboard_admin.html')

@app.route('/sessions')
def sessions():
    try:
        all_sessions = ClassSession.query.order_by(ClassSession.id.desc()).all()
        return render_template('sessions.html', sessions=all_sessions)
    except Exception as e:
        app.logger.exception("Error loading sessions")
        flash("Failed to load sessions.", "danger")
        return redirect(url_for('index'))

@app.route('/create_session', methods=['GET', 'POST'])
def create_session():
    if request.method == 'POST':
        try:
            class_name = request.form['class_name']
            new_session = ClassSession(topic=class_name, start_time=None, end_time=None, teacher_id=session.get('user_id'))
            db.session.add(new_session)
            db.session.commit()
            flash('Class session created successfully!', 'success')
            return redirect(url_for('sessions'))
        except Exception as e:
            app.logger.exception("Failed to create session")
            flash("Something went wrong while creating session.", "danger")
            return redirect(url_for('create_session'))
    return render_template('create_session.html')

@app.route('/start-session/<int:session_id>')
def start_session(session_id):
    session_obj = ClassSession.query.get_or_404(session_id)
    session_obj.is_live = True
    session_obj.start_time = datetime.utcnow()
    db.session.commit()
    flash("Session started!")
    return redirect(url_for('sessions'))

@app.route('/end-session/<int:session_id>')
def end_session(session_id):
    session_obj = ClassSession.query.get_or_404(session_id)
    session_obj.is_live = False
    session_obj.end_time = datetime.utcnow()
    db.session.commit()
    flash("Session ended!")
    return redirect(url_for('sessions'))
@app.route('/init-db')
def init_db():
    db.create_all()  # Create all tables

    def hash_password(password):
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

    defaults = [
        {"username": "Abdulla", "email": "mhatariabdulla@gmail.com", "password": "admin123", "role": "admin"},
        {"username": "Omar", "email": "teacher1@example.com", "password": "teacher123", "role": "teacher"},
        {"username": "student1", "email": "student1@example.com", "password": "student123", "role": "student"}
    ]

    created_users = []
    for u in defaults:
        existing_user = User.query.filter(
            (User.username == u["username"]) | (User.email == u["email"])
        ).first()

        if not existing_user:
            user = User(
                username=u["username"],
                email=u["email"],
                password=hash_password(u["password"]),
                role=u["role"]
            )
            db.session.add(user)
            created_users.append(u["username"])

    db.session.commit()

    if created_users:
        return f"✅ Database initialized! Created users: {', '.join(created_users)}"
    else:
        return "✅ Database initialized! No new users were added."

@app.route('/join_session/<int:session_id>')
def join_session(session_id):
    if 'user_id' not in session or 'username' not in session:
        return redirect(url_for('login', next=request.path))

    existing = Attendance.query.filter_by(user_id=session['user_id'], session_id=session_id).first()
    if not existing:
        attendance = Attendance(user_id=session['user_id'], session_id=session_id)
        db.session.add(attendance)
        db.session.commit()

    return render_template(
        'live_video_classroom.html',
        room_name=str(session_id),
        identity=session['username']
    )

@app.route('/get_token', methods=['POST'])
def get_token():
    data = request.get_json()
    room_name = data.get('room')
    identity = session.get('username', 'guest')

    if not room_name:
        return jsonify({'error': 'Room name is required'}), 400

    api_key = os.getenv('LIVEKIT_API_KEY')
    api_secret = os.getenv('LIVEKIT_API_SECRET')

    token = api.AccessToken(api_key, api_secret) \
        .with_identity(identity) \
        .with_name(identity) \
        .with_grants(api.VideoGrants(
            room_join=True,
            room=room_name,
            can_publish=True,
            can_subscribe=True
        ))

    return jsonify({'token': token.to_jwt()})

@app.route('/upload', methods=['GET', 'POST'])
def upload_resources():
    if request.method == 'POST':
        video = request.files.get('video')
        notes = request.files.get('notes')
        send_zip = request.form.get('send_zip')
        saved_files = []
        if video and allowed_file(video.filename, ALLOWED_VIDEO):
            filename = secure_filename(video.filename)
            video.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            saved_files.append(filename)
        if notes and allowed_file(notes.filename, ALLOWED_NOTES):
            filename = secure_filename(notes.filename)
            notes.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            saved_files.append(filename)
        if send_zip and saved_files:
            zip_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resources.zip')
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                for f in saved_files:
                    zipf.write(os.path.join(app.config['UPLOAD_FOLDER'], f), arcname=f)
            flash('Files uploaded and zipped successfully.')
        else:
            flash('Files uploaded successfully.')
        return redirect(url_for('upload_resources'))
    return render_template('upload.html')

@app.route('/resources')
def list_resources():
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        filetype = filename.rsplit('.', 1)[1].upper()
        files.append({'filename': filename, 'filetype': filetype})
    return render_template('resources.html', resources=files)

@app.route('/download/<path:filename>')
def download_resource(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/export-attendance')
def export_attendance():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Username', 'Email', 'Class', 'Join Time', 'Leave Time'])
    attendances = Attendance.query.join(User).join(ClassSession).all()
    for a in attendances:
        cw.writerow([a.user.username, a.user.email, a.session.topic, a.join_time, a.leave_time])
    output = si.getvalue()
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=attendance.csv'}
    )

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
            elif User.query.filter((User.username == username) | (User.email == email)).first():
                flash("⚠️ Username or email already exists.")
            else:
                new_user = User(username=username, email=email, password=password, role=role)
                db.session.add(new_user)
                db.session.commit()
                flash(f"✅ New {role} user '{username}' added.")
                return redirect(url_for('manage_users'))

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

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if session.get('role') != 'admin':
        flash("Access denied.")
        return redirect(url_for('login'))

    settings = {
        'recording': True,
        'chat': True,
        'uploads': True,
        'upload_limit': 50,
        'allowed_types': 'mp4, pdf, docx'
    }

    if request.method == 'POST':
        new_pass = request.form.get('new_password')
        if new_pass:
            user = User.query.get(session['user_id'])
            user.password = new_pass
            db.session.commit()
            flash("✅ Password updated.")

        settings['recording'] = 'enable_recording' in request.form
        settings['chat'] = 'enable_chat' in request.form
        settings['uploads'] = 'enable_uploads' in request.form
        settings['upload_limit'] = int(request.form.get('upload_limit') or 50)
        settings['allowed_types'] = request.form.get('allowed_types') or 'mp4, pdf, docx'

        flash("✅ Settings saved (but not persisted — update logic needed).")

    return render_template('admin_settings.html',
                           settings=settings,
                           livekit_url=LIVEKIT_URL,
                           livekit_key=API_KEY)

@app.route('/record')
def record():
    return render_template('record.html')

if __name__ == '__main__':
    app.run(debug=True)
