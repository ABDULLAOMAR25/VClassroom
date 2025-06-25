from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import jwt
import time
from datetime import datetime
from dotenv import load_dotenv
import os
import zipfile
import requests
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
LIVEKIT_EGRESS_URL = os.getenv("LIVEKIT_EGRESS_URL")  # ✅ Added (MUST be in .env)

# File upload configuration
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_VIDEO = {'mp4', 'mkv', 'avi'}
ALLOWED_NOTES = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt'}

# Database Configuration
db_url = os.environ.get('DATABASE_URL')
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

# --- Helper Function ---
def allowed_file(filename, allowed_ext):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_ext

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        user = User.query.filter_by(username=username, email=email, password=password, role=role).first()
        if user:
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/reset-password/<code>', methods=['GET', 'POST'])
def reset_password(code):
    user = User.query.filter_by(reset_code=code).first()
    if not user:
        return "Invalid or expired reset code."

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            return "Passwords do not match."
        user.password = new_password
        user.reset_code = None
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('reset_password.html', code=code)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    role = session.get('role')
    if role == 'student':
        return render_template('dashboard_student.html')
    elif role == 'teacher':
        return render_template('dashboard_teacher.html')
    elif role == 'admin':
        return render_template('dashboard_admin.html')
    else:
        return "Unknown role"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/create-session', methods=['GET', 'POST'])
def create_session():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return "Unauthorized", 403
    if request.method == 'POST':
        class_name = request.form['class_name']
        session_obj = ClassSession(class_name=class_name)
        db.session.add(session_obj)
        db.session.commit()
        return redirect(url_for('sessions'))
    return render_template('create_session.html')

@app.route("/sessions")
def sessions():
    all_sessions = ClassSession.query.order_by(
        ClassSession.is_live.desc(),
        ClassSession.start_time.desc().nullslast()
    ).all()
    return render_template("sessions.html", sessions=all_sessions)

@app.route('/start-session/<int:session_id>')
def start_session(session_id):
    session_obj = ClassSession.query.get_or_404(session_id)
    session_obj.is_live = True
    session_obj.start_time = datetime.now()
    db.session.commit()
    return redirect(url_for('sessions'))

@app.route('/end-session/<int:session_id>')
def end_session(session_id):
    session_obj = ClassSession.query.get_or_404(session_id)
    session_obj.is_live = False
    session_obj.end_time = datetime.now()
    db.session.commit()
    return redirect(url_for('sessions'))

@app.route('/join-session/<int:session_id>')
def join_session(session_id):
    session_obj = ClassSession.query.get_or_404(session_id)
    if session_obj.is_live:
        return render_template('join_session.html', session=session_obj)
    else:
        return "This session is not live right now."

@app.route('/record')
def record():
    return render_template("record.html")

@app.route('/get_token', methods=['POST'])
def get_token():
    data = request.get_json()
    identity = data.get('identity')
    room = data.get('room')  # this should come from frontend

    if not identity or not room:
        return jsonify({'error': 'Missing identity or room'}), 400

    payload = {
        "jti": identity + str(int(time.time())),
        "iss": API_KEY,
        "sub": identity,
        "exp": int(time.time()) + 3600,
        "video": {
            "room_join": True,
            "room": room  # ✅ fixed: using the room passed by frontend
        }
    }

    token = jwt.encode(payload, API_SECRET, algorithm="HS256")

    return jsonify({'token': token, 'url': LIVEKIT_URL})

# --- Start Recording Route ---
@app.route('/start-recording/<room_name>', methods=['POST'])
def start_recording(room_name):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return "Unauthorized", 403

    payload = {
        "iss": API_KEY,
        "exp": int(time.time()) + 60,
    }
    token = jwt.encode(payload, API_SECRET, algorithm="HS256")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    egress_payload = {
        "room_name": room_name,
        "layout": "grid",
        "output": {
            "file": {
                "filepath": f"/recordings/{room_name}_{int(time.time())}.mp4"
            }
        }
    }

    response = requests.post(LIVEKIT_EGRESS_URL, headers=headers, json=egress_payload)

    if response.status_code == 200:
        result = response.json()
        session['egress_id'] = result.get("egress_id")
        return jsonify({"message": "✅ Recording started"})
    else:
        return jsonify({"message": "❌ Failed to start recording", "details": response.text}), 500

# --- Stop Recording Route ---
@app.route('/stop-recording', methods=['POST'])
def stop_recording():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return "Unauthorized", 403

    egress_id = session.get('egress_id')
    if not egress_id:
        return jsonify({"message": "⚠️ No active recording found"})

    payload = {
        "iss": API_KEY,
        "exp": int(time.time()) + 60,
    }
    token = jwt.encode(payload, API_SECRET, algorithm="HS256")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    stop_url = LIVEKIT_EGRESS_URL.replace('/start', '/stop')
    response = requests.post(stop_url, headers=headers, json={"egress_id": egress_id})

    if response.status_code == 200:
        session.pop('egress_id', None)
        return jsonify({"message": "🛑 Recording stopped"})
    else:
        return jsonify({"message": "❌ Failed to stop recording", "details": response.text}), 500

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

# No app.run() needed for deployment
