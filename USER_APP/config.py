import pathlib

from flask import Flask

CUR_DIR = str(pathlib.Path().resolve())
if CUR_DIR.endswith('USER_APP'):
  UPLOAD_FOLDER = './user_data/uploads'
else:
  UPLOAD_FOLDER = 'USER_APP/user_data/uploads'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__, static_url_path='/FRONT_END/src', static_folder='FRONT_END/src', template_folder='FRONT_END')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Allow 2 mb of max upload
app.config['SECRET_KEY'] = 'we are the champions'


MASTER_IP = '10.17.5.95'
MASTER_URL = f'http://{MASTER_IP}:8000'
