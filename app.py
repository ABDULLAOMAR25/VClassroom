from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
import jwt
import time
from datetime import datetime
from dotenv import load_dotenv
import os
import zipfile
import requests
import csv
from io import StringIO
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

# Flask App Setup
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key')

# LiveKit Config
API_KEY = os.getenv("LIVEKIT_API_KEY")
API_SECRET = os.getenv("LIVEKIT_API_SECRET")
LIVEKIT_URL = os.getenv("LIVEKIT_URL")
LIVEKIT_EGRESS_URL = os.getenv("LIVEKIT_EGRESS_URL")

# File upload configuration
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_VIDEO = {'mp4', 'mkv', 'avi'}
ALLOWED_NOTES = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt'}

# Database Configuration
db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///classes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB
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

# --- Helper Function ---
def allowed_file(filename, allowed_ext):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_ext

@app.route('/')
def index():
    return "✅ VClassroom Flask App is running!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        flash("Invalid credentials")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

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

@app.route('/init-db')
def init_db():
    db.create_all()
    return "✅ Database initialized!"

@app.route('/export-attendance')
def export_attendance():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Username', 'Email', 'Class', 'Join Time', 'Leave Time'])

    attendances = Attendance.query.join(User).join(ClassSession).all()
    for a in attendances:
        cw.writerow([a.user.username, a.user.email, a.session.class_name, a.join_time, a.leave_time])

    output = si.getvalue()
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=attendance.csv'}
    )

@app.route('/join_session/<int:session_id>')
def join_session(session_id):
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))

    existing = Attendance.query.filter_by(user_id=session['user_id'], session_id=session_id).first()
    if not existing:
        attendance = Attendance(user_id=session['user_id'], session_id=session_id)
        db.session.add(attendance)
        db.session.commit()

    return render_template('join_session.html', room_name=session_id)

