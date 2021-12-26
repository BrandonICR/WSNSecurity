from resources import db
from db.db import User, AES, Trivium
import properties as properties
import constants.constants as constants

def create_all():
    db.create_all()
    if not User.query.filter_by(username=properties.admin_username).first():
        create_user(properties.admin_username, properties.admin_username)
    if not AES.query.filter_by(id=constants.int_one).first():
        aes = AES(key = constants.empty_hex_16B, iv = constants.empty_hex_16B)
        db.session.add(aes)
    if not Trivium.query.filter_by(id=constants.int_one).first():
        trivium = Trivium(key = constants.f_hex_10B, iv = constants.f_hex_10B)
        db.session.add(trivium)
        db.session.commit()

def create_user(username, password):
    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()

def validate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if not user:
        return None
    if user.password == password:
        return user
    return None

def set_key(key, algorithm):
    algorithm_db = None
    if algorithm == constants.str_aes:
        algorithm_db = AES.query.filter_by(id = constants.int_one).first()
    elif algorithm == constants.str_trivium:
        algorithm_db = Trivium.query.filter_by(id = constants.int_one).first()
    if algorithm_db:
        algorithm_db.key = key
        db.session.commit()
        return True
    return False

def set_iv(iv, algorithm):
    algorithm_db = None
    if algorithm == constants.str_aes:
        algorithm_db = AES.query.filter_by(id = constants.int_one).first()
    elif algorithm == constants.str_trivium:
        algorithm_db = Trivium.query.filter_by(id = constants.int_one).first()
    if algorithm_db:
        algorithm_db.iv = iv
        db.session.commit()
        return True
    return False

def get_key(algorithm):
    algorithm_db = None
    if algorithm == constants.str_aes:
        algorithm_db = AES.query.filter_by(id = constants.int_one).first()
    elif algorithm == constants.str_trivium:
        algorithm_db = Trivium.query.filter_by(id = constants.int_one).first()
    return algorithm_db.key


def get_iv(algorithm):
    algorithm_db = None
    if algorithm == constants.str_aes:
        algorithm_db = AES.query.filter_by(id = constants.int_one).first()
    elif algorithm == constants.str_trivium:
        algorithm_db = Trivium.query.filter_by(id = constants.int_one).first()
    return algorithm_db.iv