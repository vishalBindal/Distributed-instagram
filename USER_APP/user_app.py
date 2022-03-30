from __future__ import annotations

import json
import logging
import pickle

from flask import Flask, redirect, url_for, render_template, request, flash
from datetime import datetime
import requests

from utils import get_ip_address, generate_key_pair
from config import MASTER_IP, MASTER_URL
from pathlib import Path
from typing import Optional, List, Dict, Any
from flask_login import LoginManager
import urllib.parse
import redis

app = Flask(__name__, static_url_path='/FRONT_END/src', static_folder='FRONT_END/src', template_folder='FRONT_END')
app.config['SECRET_KEY'] = 'we are the champions'

LOCAL_USER_PKL_PATH = './user_data/user.pkl'

# Setting up auth
login_manager = LoginManager()
login_manager.init_app(app)


class UserMismatch(Exception):
  pass


class User:
  USER_DATA_KEY = 'user_data'
  DECRYPT_FOLLOWING_KEY = 'decrypt_following_key'
  required_keys = ['username', 'm_key', 'key2_encrypt', 'key2_decrypt', 'creation_time']

  def __init__(self, username: str = '', m_key: str = '', key2_encrypt: bytes = b'', key2_decrypt: bytes = b''):
    self.loaded = False
    self.rds = redis.Redis(host=self.get_user_ip_address(), decode_responses=True, socket_timeout=5)
    self.user_data: Dict[str, Any] = {'username': username, 'm_key': m_key, 'key2_encrypt': key2_encrypt,
                                      'key2_decrypt': key2_decrypt, 'creation_time': datetime.now()}
    self.key2_decrypt_following: Dict[str, bytes] = dict()

  def get_username(self):
    self.load()
    return self.user_data['username']

  def get_m_key(self):
    self.load()
    return self.user_data['m_key']

  def key2_encrypt(self):
    self.load()
    return self.user_data['key2_encrypt']

  def get_key2_decrypt(self):
    self.load()
    return self.user_data['key2_decrypt']

  def add_following(self, username2: str, following_decrypt_key: bytes):
    """This function will be called after someone accepts your follow request. That person who accept will send decrypt
    key to master and master will send it to you through a post request and then this function will be called."""
    self.key2_decrypt_following[username2] = following_decrypt_key
    self.rds.hset(name=self.DECRYPT_FOLLOWING_KEY, key=username2, value=following_decrypt_key)

  @staticmethod
  def get_user_ip_address():
    return get_ip_address()

  def get_followers(self):
    r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'followers'), params={'name': self.get_username()})
    data = r.json()
    followers: List[str] = data['followers']
    return followers

  def get_following(self):
    r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'following'), params={'name': self.get_username()})
    data = r.json()
    following: List[str] = data['following']
    return following

  def get_pending_requests(self):
    r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'pending_requests'), params={'name': self.get_username()})
    data = r.json()
    pending_requests: List[str] = data['following']
    return pending_requests

  def accept_request(self, username2: str) -> bool:
    if self.get_key2_decrypt() == '':
      logging.debug('Currently the key2_decrypt has not been recovered')
      return False
    else:
      r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'accept_request'), data={
        'm_key': self.get_m_key(),
        'username2': username2,
        'key2_decrypt': self.get_key2_decrypt()
      })
      response = dict(r.text)
      if not response['success']:
        logging.debug(response['err'])
        return False

  def load(self) -> int:
    """returns number of elements loaded from redis. If redis didn't have the data then it would return 0"""
    if not self.loaded:
      # Populating self
      user_data = self.rds.hgetall(name=self.USER_DATA_KEY)
      for key in self.required_keys:
        if key not in user_data:
          logging.debug('Inconsistent data in redis')
          return 0
      c = 0
      for key in self.required_keys:
        if self.user_data[key] != user_data[key]:
          c += 1
      self.user_data = user_data
      self.loaded = True
      self.key2_decrypt_following = self.rds.hgetall(self.DECRYPT_FOLLOWING_KEY)
      return c

  def save(self):
    self.loaded = True
    self.rds.delete(self.USER_DATA_KEY, self.DECRYPT_FOLLOWING_KEY)
    self.rds.hmset(name=self.USER_DATA_KEY, mapping=self.user_data)
    self.rds.hmset(name=self.DECRYPT_FOLLOWING_KEY, mapping=self.key2_decrypt_following)

  def get_creation_time_str(self) -> str:
    # dd/mm/YY H:M:S
    self.load()
    dt_string = self.user_data['creation_time'].strftime("%d/%m/%Y %H:%M:%S")
    return dt_string

  def try_recovery(self):
    # TODO: Do this recovery in celery so as to make it fault tolerant
    # If master is down user keeps trying thorugh celery task

    # ------ put this inside celery task and starts async ------
    r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'reset_following'), data={'m_key': self.m_key})
    # Following will be empty since I don't have any ones key2_decrypt. So, you will need to follow everyone again
    # TODO: Send request to recover key2_decrypt from followers asynchronously
    # Keep trying to recover for some time (Say 5 minutes for the purpose of this assignment)
    # But is it safe to ask for decrypt key ?
    self.save()

  @staticmethod
  def log_user_in(username: str, m_key: str, key2_encrypt: bytes):
    user = User(username=username, m_key=m_key, key2_encrypt=key2_encrypt)

    # Checking if user in local storage is same as the one logging in
    c = user.load()
    if c > 0:
      params_len = len(locals())
      if c != len(user.required_keys) - len(locals()):
        raise UserMismatch
    else:
      user.try_recovery()

  @staticmethod
  def create_new_user(username: str, m_key: str, key2_encrypt: bytes, key2_decrypt: bytes):
    user = User(username, m_key, key2_encrypt, key2_decrypt)
    user.save()


@login_manager.user_loader
def load_user(user_id):
  user = User()
  user.load()
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

  r = requests.post(url=MASTER_URL, data={
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

  r: requests.models.Response = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'new_user'), data={
    'name': username,
    'password': password,
    'key2_encrypt': key2_encrypt,
    'node_ip': get_ip_address()
  })

  response = json.loads(r.content)
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
  logging.basicConfig(level=logging.DEBUG)
  app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
