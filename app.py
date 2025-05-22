from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

app = Flask(__name__)

# --- Fix DATABASE_URL for SQLAlchemy compatibility ---
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///classes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Model ---
class ClassSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    is_live = db.Column(db.Boolean, default=False)

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('sessions'))

@app.route('/create-session', methods=['GET', 'POST'])
def create_session():
    if request.method == 'POST':
        class_name = request.form['class_name']
        session = ClassSession(class_name=class_name)
        db.session.add(session)
        db.session.commit()
        return redirect(url_for('sessions'))
    return render_template('create_session.html')

@app.route('/sessions')
def sessions():
    all_sessions = ClassSession.query.all()
    return render_template('sessions.html', sessions=all_sessions)

@app.route('/start-session/<int:session_id>')
def start_session(session_id):
    session = ClassSession.query.get_or_404(session_id)
    session.is_live = True
    session.start_time = datetime.now()
    db.session.commit()
    return redirect(url_for('sessions'))

@app.route('/end-session/<int:session_id>')
def end_session(session_id):
    session = ClassSession.query.get_or_404(session_id)
    session.is_live = False
    session.end_time = datetime.now()
    db.session.commit()
    return redirect(url_for('sessions'))

@app.route('/join-session/<int:session_id>')
def join_session(session_id):
    session = ClassSession.query.get_or_404(session_id)
    if session.is_live:
        return render_template('join_session.html', session=session)
    else:
        return "This session is not live right now."
