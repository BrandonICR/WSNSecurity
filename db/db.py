from resources import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=True, nullable=False)

class AES(db.Model):
    __tablename__ = 'aes'
    id = db.Column(db.Integer, primary_key=True)
    iv = db.Column(db.String(32), unique=True, nullable=False)
    key = db.Column(db.String(32), unique=True, nullable=False)

class Trivium(db.Model):
    __tablename__ = 'trivium'
    id = db.Column(db.Integer, primary_key=True)
    iv = db.Column(db.String(20), unique=True, nullable=False)
    key = db.Column(db.String(20), unique=True, nullable=False)
