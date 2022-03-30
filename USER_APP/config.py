from flask import Flask

UPLOAD_FOLDER = './user_data/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Allow 2 mb of max upload

MASTER_IP = '192.168.0.0'  # TODO: Add Master Node IP
MASTER_URL = f'{MASTER_IP}:8000'
