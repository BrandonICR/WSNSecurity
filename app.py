import json
import db.db_handler as db_handler
import re

from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_login import login_user, login_required, logout_user
from resources import create_app
from log.logger import get_registry
from client.uart_client_handler import inicializar_lectura, enviar_texto_cifrado, test_uart, enviar_key
from utils.utils import to_bytes
from properties import admin_username, admin_password
from cryptography.trivium import Trivium
from cryptography.aes128 import AES128
from db.db import User
from cryptography import test_algorithms

app, login_manager = create_app()

context = {
    'uart_status':False,
    'algorithm':'',
    'decrypt_ciphertext':'',
    'lastCipher':'',
    'lastPlainText':'',
    'lastCipherText':'',
    'lastDecryptCiphertext':'',
    'currentIV':'',
    'currentKey':''
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/home")
@login_required
def home():
    if context['currentIV'] == '' and context['algorithm'] != '':
        context['currentIV'] = db_handler.get_iv(context['algorithm'])
    if context['currentKey'] == '' and context['algorithm'] != '':
        context['currentKey'] = db_handler.get_key(context['algorithm'])
    return render_template('home.html', context=context)

@app.route("/cifrar", methods=['POST'])
@login_required
def cifrar():
    if request.method == 'POST':
        global context
        print('Estado comunicacion antes de cifrar:', context['uart_status'])
        if not context['uart_status']:
            return {'error':'FAIL'}
        plaintext = request.form['plaintext']
        encoding = request.form['encoding']
        print("plaintext:", plaintext)
        plaintext = to_bytes(plaintext,encoding)
        response = enviar_texto_cifrado(context['algorithm'], plaintext, encoding)
        context['decrypt_ciphertext'] = re.sub(r'\x00', '', response['plaintext'])
        context['lastCipher'] = response['date']
        context['lastPlainText'] = re.sub(r'\x00', '', request.form['plaintext'])
        context['lastCipherText'] = re.sub(r'\x00', '', response['ciphertext'])
        context['lastDecryptCiphertext'] = ''
        response.pop('plaintext')
        return response


@app.route("/decifrar", methods=['POST'])
@login_required
def decifrar():
    if request.method == 'POST':
        decrypt = context['decrypt_ciphertext']
        context['lastDecryptCiphertext'] = decrypt
        return decrypt

@app.route("/registro")
@login_required
def registro():
    return render_template('registry.html',registry=get_registry())

@app.route("/profile")
@login_required
def profile():
    return render_template('profile.html', context=context)

@app.route("/prueba")
@login_required
def prueba():
    return render_template('prueba.html', context=context)

@app.route("/test", methods=['POST'])
@login_required
def test_communication():
    global context
    msg = test_uart()
    print("TEST RESULT:",msg)
    uart_status = msg != b'FAIL' and msg != b''
    context['uart_status'] = uart_status
    if uart_status:
        algorithm = msg.decode('latin 1')
        context['algorithm'] = algorithm
        context['currentIV'] = db_handler.get_iv(algorithm)
        return {'algorithm': algorithm, 'currentIV': context['currentIV']}
    context['algorithm'] = ''
    return 'FAIL'

@app.route("/test_algorithm", methods=['POST'])
@login_required
def test_algorithm():
    algorithm = request.form['algorithm']
    key = request.form['key']
    iv = request.form['iv']
    plaintext = request.form['plaintext']
    if algorithm == 'TRIVIUM':
        return test_algorithms.TriviumTest(key, iv).decrypt(plaintext)
    return test_algorithms.AES128Test.encrypt(key, iv, plaintext)

@app.route("/change_key", methods=['POST'])
@login_required
def change_key():
    if request.method == 'POST':
        key_str = request.form['key']
        print("Recibida peticion de cambio de llave")
        key = to_bytes(key_str, 'hex')
        test = enviar_key(key, context['algorithm'])
        if test != 'FAIL':
            context['lastCipher'] = ''
            context['lastPlainText'] = ''
            context['lastCipherText'] = ''
            context['lastDecryptCiphertext'] = ''
            context['currentKey'] = key_str
        return test

@app.route("/login", methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db_handler.validate_user(username, password)
        if user:
            login_user(user)
            context['uart_status'] = False
            context['algorithm'] = ''
            context['decrypt_ciphertext'] = ''
            context['lastCipher'] = ''
            context['lastPlainText'] = ''
            context['lastCipherText'] = ''
            context['lastDecryptCiphertext'] = ''
            context['currentIV'] = ''
            context['currentKey'] = ''
            return redirect(url_for('home'))
        return redirect(url_for('index'))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__":
    msg = inicializar_lectura()
    print(msg)
    context['uart_status'] = msg != b'FAIL' and msg != b''
    print(context['uart_status'])
    db_handler.create_all()
    Trivium.inicializacion()
    AES128.set_default_key_iv()
    app.run(debug=False)
