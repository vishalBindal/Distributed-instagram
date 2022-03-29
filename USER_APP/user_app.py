from __future__ import annotations

import pickle

from flask import Flask, redirect, url_for, render_template, request, flash, json
from datetime import datetime
import requests

from utils import get_ip_address, generate_key_pair
from config import MASTER_IP
from pathlib import Path
import socket
from typing import Optional, List, Dict, Tuple
from flask_login import LoginManager
import urllib.parse

app = Flask(__name__, static_url_path='/FRONT_END/src', static_folder='FRONT_END/src', template_folder='FRONT_END')
app.config['SECRET_KEY'] = 'we are the champions'

LOCAL_USER_PKL_PATH = './user_data/user.pkl'

# Setting up auth
login_manager = LoginManager()
login_manager.init_app(app)


class UserMismatch(Exception):
  pass


class User:
  def __init__(self, username: str, m_key: str, key2_encrypt: bytes, key2_decrypt: bytes = b''):
    self.username = username
    self.key2_encrypt = key2_encrypt
    self.m_key = m_key
    self.key2_decrypt = key2_decrypt

    self.followers: List[str] = []
    self.following: List[str] = []
    self.key2_decrypt_following: Dict[str, str] = dict()

    self.ip_address = get_ip_address()
    self.creation_time = datetime.now()

  @staticmethod
  def log_user_in(username: str, m_key: str, key2_encrypt: bytes):
    user = User(username=username, m_key=m_key, key2_encrypt=key2_encrypt)

    # Checking if user in local storage is same as the one logging in
    user_local: User = User.load()
    if user_local is not None:
      if user_local.username != username or user_local.key2_encrypt != key2_encrypt or user_local.m_key != m_key:
        raise UserMismatch
    else:
      # We don't have the user in local storage. Try to recover the user
      profile_data = requests.get(url=MASTER_IP + ':8000/profile_data', params={'name': username}).json()
      user.followers = profile_data['followers']
      user.following = []  # Following will not be empty since I don't have any ones key2_decrypt. So, you will
      # need to follow everyone again

      # TODO: Send request to recover key2_decrypt from followers asynchronously
      # Keep trying to recover for some time (Say 5 minutes for the purpose of this assignment)
      # But is it safe to ask for decrypt key ?

    user.save()

  @staticmethod
  def create_new_user(username: str, m_key: str, key2_encrypt: bytes, key2_decrypt: bytes):
    user = User(username, m_key, key2_encrypt, key2_decrypt)
    user.save()

  @staticmethod
  def load() -> Optional[User]:
    if not Path(LOCAL_USER_PKL_PATH).is_file():
      return None

    with open(LOCAL_USER_PKL_PATH, 'rb') as handle:
      user = pickle.load(handle)

    if not isinstance(user, User):
      return None

    return user

  def save(self):
    with open(LOCAL_USER_PKL_PATH, 'wb') as handle:
      pickle.dump(self, handle)

  def set_user_name(self):
    pass

  def get_creation_time(self):
    # dd/mm/YY H:M:S
    dt_string = self.creation_time.strftime("%d/%m/%Y %H:%M:%S")
    return dt_string


@login_manager.user_loader
def load_user(user_id):
  user = User.load()
  return user


@app.route('/err', methods=['GET'])
def err():
  return render_template('error.html', error='toto')


@app.route("/login")
def login(name=''):
  return render_template('login.html', name=name)


@app.route("/login", methods=['POST'])
def login_post():
  name = request.form.get('name')
  password = request.form.get('password')

  r = requests.post(url=MASTER_IP, data={
    'name': name,
    'password': password
  })
  response = dict(r.text)

  if not response['success']:
    if response['err'] == 1:
      flash('Account not found. Please register first.')
      return redirect(url_for('login', name=name))

    elif response['err'] == 2:
      flash('Incorrect password.')
      return redirect(url_for('login', name=name))

  m_key, key2_encrypt = response['m_key'], response['key2_encrypt']

  try:
    user = User(username=name, key2_encrypt=key2_encrypt, m_key=m_key)
  except UserMismatch as e:
    msg = 'The user object in local storage is not the same as the one used to log in. Please either remove the ' \
          'local storage or double-check that the data transferred from the previous device is accurate.'
    return render_template('error.html', error=msg)

  # TODO: html page for dashboard
  return redirect(url_for('dashboard'))


@app.route("/register")
def register(username=''):
  return render_template('register.html', username=username)


@app.route("/register", methods=['POST'])
def register_post():
  username = request.form.get('username')
  password = request.form.get('password')

  key2_encrypt, key2_decrypt = generate_key_pair()

  master_url = f'{MASTER_IP:8000}'
  r = requests.post(url=urllib.parse.urljoin(master_url, 'new_user'), data={
    'name': username,
    'password': password,
    'key2_encrypt': key2_encrypt,
    'node_ip': get_ip_address()
  })

  response = dict(r.text)
  success: bool = response['success']
  if not success:
    error_msg: str = response['error']
    flash(f'Error: {error_msg} Unsuccessful. Try again')
    return render_template('register.html', username=username)
  else:
    try:
      m_key: str = response['m_key']
      User.create_new_user(username=username, m_key=m_key, key2_encrypt=key2_encrypt, key2_decrypt=key2_decrypt)
      # User saved the user to local storage
      return redirect(url_for('dashboard'))
    except Exception as e:
      flash(str(e))
      return render_template('register.html', username=username)



@app.route("/")
def index():
  return render_template('front_page.html')


# TODO: define more functions as given in doc


if __name__ == "__main__":
  # if not first time then remove this
  app.run(debug=True, port=8000)
