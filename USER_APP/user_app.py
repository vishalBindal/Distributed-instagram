from __future__ import annotations

import json
import logging
import os
import pickle

import rsa as rsa
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
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


# TODO: Make all imp post request in celery to keep trying again

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
  IMAGE_DATA = 'image_data'

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
    return not self.get_username() == ''

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
    for key in self.user_data:
      if self.user_data[key] == '':
        raise Exception('Can\'t save. The local object is not populated fully.')
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
    r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'reset_following'), data={'m_key': self.user_data['m_key']})
    # Following will be empty since I don't have any ones key2_decrypt. So, you will need to follow everyone again
    # TODO: Send request to recover key2_decrypt from followers asynchronously
    # Keep trying to recover for some time (Say 5 minutes for the purpose of this assignment)
    # But is it safe to ask for decrypt key ?
    self.save()

  def is_consistent_with_rds(self):
    rds_user_data = self.rds.hgetall(name=self.USER_DATA_KEY)
    for key in self.required_keys:
      if key in rds_user_data and rds_user_data[key] != self.user_data[key]:
        return False
    return True

  def add_image_data(self, unique_hash: str, encoded_info: str):
    self.rds.hset(name=self.IMAGE_DATA, key=unique_hash, value=encoded_info)
    pass


def log_user_in(username: str, m_key: str, key2_encrypt: str):
  params_len = len(locals())
  user = User(username=username, m_key=m_key, key2_encrypt=key2_encrypt)

  # Checking if user in local storage is same as the one logging in
  c = user.load()
  if c == 0:
    # No data in local
    user.save()
    user.try_recovery()
  if c > 0:
    if c != len(user.required_keys) - len(locals()):
      raise UserMismatch
  return user


def create_new_user(username: str, m_key: str, key2_encrypt: str, key2_decrypt: str):
  user = User(username, m_key, key2_encrypt, key2_decrypt)
  user.save()


@app.route('/err', methods=['GET'])
def err():
  return render_template('error.html', error='toto')


@app.route("/login")
def login(name=''):
  user = User()
  user.load()
  return render_template('login.html', user=user, name=name)


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
    log_user_in(username=name, key2_encrypt=key2_encrypt, m_key=m_key)
  except UserMismatch:
    flash('The user object in local storage is not the same as the one used to log in. Please either remove the local '
          'storage or double-check that the data transferred from the previous device is accurate.')
    return render_template('login.html', user=User())

  return redirect(url_for('profile'))


@app.route("/register")
def register(username=''):
  user = User()
  user.load()
  return render_template('register.html', user=user)


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
    error_msg: str = response['error_msg']
    flash(f'Error: {error_msg} Unsuccessful. Try again')
    return render_template('register.html', user=User())
  else:
    try:
      m_key: str = response['m_key']
      create_new_user(username=username, m_key=m_key, key2_encrypt=key2_encrypt, key2_decrypt=key2_decrypt)
      # User saved the user to local storage
      return redirect(url_for('profile'))
    except Exception as e:
      flash(str(e))
      return render_template('register.html', user=User())


@app.route("/profile/<username>")
def profile2(username):
  user = User(username=username)
  return render_template('other_profile.html', user=user, followers=user.get_followers(), following=user.get_following())


@app.route("/profile")
def profile():
  user = User()
  user.load()
  if not user.is_logged_in():
    flash('You are not logged in. Log in to view profile')
    return render_template('login.html', user=user)
  else:
    return render_template('profile.html', user=user, followers=user.get_followers(), following=user.get_following())


@app.route("/")
def index():
  user = User()
  user.load()
  return render_template('front_page.html',user=user)


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
      r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'nearby_nodes'),
                        data={'node_ip': user.get_user_ip_address()})
      response = r.text

      # TODO: check if file is actually bytes o.w load from filepath
      try:
        nd_ids = dict(response)

        # https://stackoverflow.com/questions/28426102/python-crypto-rsa-public-private-key-with-large-file
        aes_key = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_EAX)
        data = open(file.filename, 'rb').read()
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Now aes_key using encrypt key
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(user.get_key2_encrypt().encode()))
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        encoded_info_dict = {'nonce': cipher.nonce, 'ciphertext': ciphertext, 'tag': tag,
                             'encrypted_aes_key': encrypted_aes_key}
        encoded_info = pickle.dumps(encoded_info_dict)

        # Decrypt example: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
        # Decrypt aes_key using rsa and then decrypt image using that aes_key

        for nd_id in nd_ids:
          nd_url = f'http://{nd_id}:8000'
          r = requests.post(url=urllib.parse.urljoin(nd_url, 'add_image_data'), data={
            'encoded_info': encoded_info
          })
          response = json.loads(r.content)

          if not response['success']:
            logging.debug(f'failed writing on node {nd_url}')
      except Exception as e:
        print(e)
        return e

      return redirect(url_for('download_file', name=filename))


@app.route('/add_image_data')
def add_image_data():
  data = request.form
  try:
    unique_hash = data['unique_hash']
    encoded_info = data['encoded_info']
  except Exception as e:
    logging.debug(e)
    return {'success': False}
  user = User()
  user.load()
  if not user.is_logged_in():
    return {'success': False, 'err': 'user is not logged in on this node'}
  else:
    user.add_image_data(unique_hash=unique_hash, encoded_info=encoded_info)
    return {'success': True}


@app.route('/uploads/<name>')
def download_file(name):
  return send_from_directory(app.config["UPLOAD_FOLDER"], name)


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  app.add_url_rule(
    "/user_data/<name>", endpoint="download_file", build_only=True
  )
  app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
