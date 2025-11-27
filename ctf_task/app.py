import json
import base64
import os
import random
from flask import Flask, render_template, request, redirect, make_response, url_for, flash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = "ash_chronicles_internal_key"

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

FLAG = "CTF{D0_N0T_ST0R3_K3YS_0N_CL13NT_S1D3}"
SECRET_KEY = b'ObsidianWallKey!' 
INIT_VECTOR = b'ShadowGateKeepr!' 

LORE_PHRASES = [
    "Ключи к власти часто оставляют на самом видном месте... в коде мироздания.",
    "Не ищи ответы в Бездне, посмотри в инструменты своего созерцания.",
    "Печать создается там же, где и читается.",
]

class AESCipher:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, raw_data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        json_bytes = json.dumps(raw_data).encode('utf-8')
        encrypted = cipher.encrypt(pad(json_bytes, AES.block_size))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, enc_data):
        try:
            enc_data = base64.b64decode(enc_data)
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decrypted = unpad(cipher.decrypt(enc_data), AES.block_size)
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            return None

cipher_suite = AESCipher(SECRET_KEY, INIT_VECTOR)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image_header(stream):
    header = stream.read(6)
    stream.seek(0)
    if header in [b'GIF87a', b'GIF89a']:
        return True
    return False

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            session_data = {
                "user": username,
                "role": "guest", 
                "exp": 9999999999
            }
            encrypted_token = cipher_suite.encrypt(session_data)
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('auth_token', encrypted_token)
            return resp
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('auth_token')
    if not token:
        return redirect(url_for('login'))

    data = cipher_suite.decrypt(token)
    if not data:
        return "Ошибка чтения памяти (Invalid Token)", 400

    display_role = "НАБЛЮДАТЕЛЬ"
    if data.get('role') == 'admin':
        display_role = "ХРАНИТЕЛЬ"

    random_phrase = random.choice(LORE_PHRASES)

    return render_template('dashboard.html', 
                           user=data.get('user'), 
                           role=display_role, 
                           phrase=random_phrase) 

@app.route('/upload', methods=['POST'])
def upload_file():
    token = request.cookies.get('auth_token')
    if not token or not cipher_suite.decrypt(token):
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('Запись не выбрана.')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Пустое имя записи.')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        if not validate_image_header(file.stream):
            flash('ОШИБКА: Файл поврежден или подделан.')
            return redirect(url_for('dashboard'))

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        flash('Запись принята в буфер обмена. Ожидайте верификации Хранителем.')
        return redirect(url_for('dashboard'))
    else:
        flash('Принимаются только визуальные проекции (GIF).')
        return redirect(url_for('dashboard'))

@app.route('/admin_panel')
def admin():
    token = request.cookies.get('auth_token')
    if not token:
        return redirect(url_for('login'))

    data = cipher_suite.decrypt(token)
    
    if data and data.get('role') == 'admin':
        return render_template('admin.html', flag=FLAG)
    else:
        return render_template('error.html'), 403

@app.errorhandler(413)
def request_entity_too_large(error):
    flash("Слишком объемное воспоминание (Лимит 2 МБ).")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)