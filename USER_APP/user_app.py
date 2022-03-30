from __future__ import annotations

import json
import logging
import os
import pickle

import rsa as rsa
from flask import Flask, redirect, url_for, render_template, request, flash, send_from_directory
from datetime import datetime
import requests
from werkzeug.utils import secure_filename

from utils import get_ip_address, generate_key_pair, allowed_file
from config import MASTER_URL
from pathlib import Path
from typing import Optional, List, Dict, Any
import urllib.parse
import redis

app = Flask(__name__, static_url_path='/FRONT_END/src', static_folder='FRONT_END/src', template_folder='FRONT_END')
app.config['SECRET_KEY'] = 'we are the champions'

LOCAL_USER_PKL_PATH = './user_data/user.pkl'


class UserMismatch(Exception):
  pass


def get_followers(username: str) -> List[str]:
  r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'followers'), params={'name': username})
  data = r.json()
  followers = data['followers']
  return followers


def get_following(username: str) -> List[str]:
  r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'following'), params={'name': username})
  data = r.json()
  following = data['following']
  return following


class User:
  USER_DATA_KEY = 'user_data'
  DECRYPT_FOLLOWING_KEY = 'decrypt_following_key'
  required_keys = ['username', 'm_key', 'key2_encrypt', 'key2_decrypt', 'creation_time']

  def __init__(self, username: str = '', m_key: str = '', key2_encrypt: str = '', key2_decrypt: str = ''):
    self.loaded = False
    self.rds = redis.Redis(decode_responses=True, socket_timeout=5)
    self.user_data: Dict[str, Any] = {'username': username, 'm_key': m_key, 'key2_encrypt': key2_encrypt,
                                      'key2_decrypt': key2_decrypt, 'creation_time': self.get_current_time_str()}
    self.key2_decrypt_following: Dict[str, str] = dict()

  def get_username(self):
    self.load()
    return self.user_data['username']

  def get_m_key(self):
    self.load()
    return self.user_data['m_key']

  def get_key2_encrypt(self):
    self.load()
    return self.user_data['key2_encrypt']

  def get_key2_decrypt(self):
    self.load()
    return self.user_data['key2_decrypt']

  def get_creation_time(self) -> str:
    self.load()
    return self.user_data['creation_time']

  def add_following(self, username2: str, following_decrypt_key: str):
    """This function will be called after someone accepts your follow request. That person who accept will send decrypt
    key to master and master will send it to you through a post request and then this function will be called."""
    self.key2_decrypt_following[username2] = following_decrypt_key
    self.rds.hset(name=self.DECRYPT_FOLLOWING_KEY, key=username2, value=following_decrypt_key)

  def is_logged_in(self) -> bool:
    return self.get_username() == ''

  @staticmethod
  def get_user_ip_address():
    return get_ip_address()

  def get_followers(self):
    return get_followers(self.get_username())

  def get_following(self):
    return get_following(self.get_username())

  def get_pending_requests(self):
    r: requests.models.Response = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'pending_requests'),
                                                data={'mkey': self.get_m_key()})

    data = json.loads(r.content)
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
    if len(self.key2_decrypt_following) > 0:
      self.rds.hmset(name=self.DECRYPT_FOLLOWING_KEY, mapping=self.key2_decrypt_following)

  @staticmethod
  def get_current_time_str() -> str:
    # dd/mm/YY H:M:S
    dt = datetime.now()
    dt_string = dt.strftime("%d/%m/%Y %H:%M:%S")
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
  def log_user_in(username: str, m_key: str, key2_encrypt: str):
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
  def create_new_user(username: str, m_key: str, key2_encrypt: str, key2_decrypt: str):
    user = User(username, m_key, key2_encrypt, key2_decrypt)
    user.save()


@app.route('/err', methods=['GET'])
def err():
  return render_template('error.html', error='toto')


@app.route("/login")
def login(name=''):
  return render_template('login.html', name=name)


@app.route('/follow_accepted', methods=['POST'])
def follow_accepted():
  username2 = request.form.get('username2')
  key2_decrypt = request.form.get('key2_decrypt')
  user = User()
  user.load()
  if not user.is_logged_in():
    return {'success': False, 'err': 'user is not logged in on this node'}
  else:
    user.add_following(username2=username2, following_decrypt_key=key2_decrypt)
    return {'success': True}


@app.route("/login", methods=['POST'])
def login_post():
  name = request.form.get('name')
  password = request.form.get('password')

  r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'login_user'), data={
    'name': name,
    'password': password
  })
  response = json.loads(r.content)

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


@app.route("/profile/<username>")
def profile(username):
  user = User(username=username)
  return render_template('profile.html', user=user, followers=user.get_followers(), following=user.get_following())


@app.route("/profile")
def profile():
  user = User()
  user.load()
  if not user.is_logged_in():
    flash('You are not logged in. Log in to view dashboard')
    return render_template('login.html', user=user)
  else:
    return render_template('profile.html', user=user, followers=user.get_followers(), following=user.get_following())


@app.route("/")
def index():
  return render_template('front_page.html')


# TODO: define more functions as given in doc


@app.route('/upload_pic', methods=['POST'])
def upload_pic():
  user = User()
  user.load()
  if not user.is_logged_in():
    flash('You are not logged in. Log in to view dashboard')
    return render_template('login.html', user=user)
  else:
    # check if the post request has the file part
    if 'file' not in request.files:
      flash('No file part')
      return redirect(request.url)
    file = request.files['file']
    # If the user does not select a file, the browser submits an
    # empty file without a filename.
    if file.filename == '':
      flash('No selected file')
      return redirect(request.url)
    if file and allowed_file(file.filename):
      filename_prefix = str(datetime.now().date()) + '_' + \
                        str(datetime.now().time()).replace(':', '.') + str(user.get_username())
      filename = filename_prefix + secure_filename(file.filename)
      file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

      # Process File
      # TODO: Do this asyncly on celery
      r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'nearby_nodes'), data={'node_ip': user.get_user_ip_address()})
      response = r.text
      try:
        nd_ids = dict(response)
        e_blog_data = rsa.encrypt(data=file, pub_key=user.get_key2_encrypt().encode())
        for no_id in nd_ids:
          rds: Redis = get_rds_connection(no_id)  # self.conns[i]
          n = rds.hset(name='images', key=filename, value=e_blog_data)
          assert n == 1
      except Exception as e:
        print(e)
        return e

      return redirect(url_for('download_file', name=filename))

@app.route('/uploads/<name>')
def download_file(name):
  return send_from_directory(app.config["UPLOAD_FOLDER"], name)



if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  app.add_url_rule(
    "/user_data/<name>", endpoint="download_file", build_only=True
  )
  app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
