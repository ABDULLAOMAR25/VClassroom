from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///classes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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

with app.app_context():
    db.create_all()

    # Add sample users
    user1 = User(username='teacher1', email='teacher1@example.com', password='pass123', role='teacher')
    user2 = User(username='student1', email='student1@example.com', password='pass123', role='student')
    db.session.add_all([user1, user2])

    # Add sample class session
    session1 = ClassSession(class_name='Math 101', start_time=datetime.now(), is_live=False)
    db.session.add(session1)

    db.session.commit()

print("Database 'classes.db' created with sample data.")
