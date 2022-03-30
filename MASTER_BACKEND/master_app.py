import logging
import secrets
import string

from flask import Flask, redirect, url_for, render_template, request, flash, json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime
import redis
from abc import ABC
from config import MASTER_IP
import bcrypt
import time

app = Flask(__name__, static_url_path='/FRONT_END/src', static_folder='FRONT_END/src', template_folder='FRONT_END')
app.config['SECRET_KEY'] = 'we are the champions'


class MasterRedis(ABC):
  USERNAMES = 'usernames'
  USER2PASS = 'username_to_password'
  USER2KEY2E = 'username_to_key2_encrypt'
  MKEY2USER = 'm_key_to_username'
  USER2MKEY = 'username_to_m_key'
  USER2IMG_SUFFIX = '_img'

  USER2IP = 'username_to_ip'
  USER2LOC = 'username_to_location'
  USER2TS = 'username_to_timestamp'
  IMG2USER_SUFFIX = '_user'

  USER2FOLLOWERS_SUFFIX = '_followers'
  USER2FOLLOWING_SUFFIX = '_following'
  USER2PENDING_SUFFIX = '_pending'

  def __init__(self, master_ip):
    self.rds = redis.Redis(host=master_ip, decode_responses=True, socket_timeout=5)

  def initialize(self):
    self.rds.flushall()

    # setup USERNAMES
    self.rds.sadd(self.USERNAMES, "foo")
    # Setup USER2PASS
    self.rds.hset(self.USER2PASS, "foo", "foo")
    # Setup USER2KEY2E
    self.rds.hset(self.USER2KEY2E, "foo", "foo")
    # Setup MKEY2USER
    self.rds.hset(self.MKEY2USER, "foo", "foo")
    # Setup USER2MKEY
    self.rds.hset(self.USER2MKEY, "foo", "foo")

    # Setup USER2IP
    self.rds.hset(self.USER2IP, "foo", "foo")
    # Setup USER2LOC
    self.rds.hset(self.USER2LOC, "foo", "foo")
    # Setup USER2TS
    self.rds.hset(self.USER2TS, "foo", "foo")

  def add_image_to_user(self, username, image_hash, time_of_upload):
    # User "username" has uploaded image to her profile
    sorted_set_name = username + self.USER_IMG_SUFFIX
    self.rds.zadd(sorted_set_name, {image_hash, time_of_upload})

  def add_user_to_image(self, username, image_hash):
    # Image is stored at node corresponding to username
    set_name = image_hash + self.IMG2USER_SUFFIX
    self.rds.sadd(set_name, username)

  def add_follow_request(self, user_follower, user_profile):
    # "user_follower" wants to follow "user_profile"
    set_name = user_profile + self.USER2PENDING_SUFFIX
    self.rds.sadd(set_name, user_follower)

  def accept_follow_request(self, user_follower, user_profile):
    # "user_profile" accepts "user_follower"'s follow request
    set_name = user_profile + self.USER2PENDING_SUFFIX
    self.rds.srem(set_name, user_follower)
    set_name = user_profile + self.USER2FOLLOWERS_SUFFIX
    self.rds.sadd(set_name, user_follower)
    set_name = user_follower + self.USER2FOLLOWING_SUFFIX
    self.rds.sadd(set_name, user_profile)


mr = MasterRedis(MASTER_IP)


def get_master_rds():
  return MasterRedis(MASTER_IP)


def generate_mkey():
  # generating random string of length 512
  key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(512))
  return key


@app.route('/new_user', methods=['POST'])
def new_user():
  data = request.get_json()
  try:
    name = data.name
    password = data.password
    key2_encrypt = data.key2_encrypt
    node_ip = data.node_ip
  except Exception as e:
    print(f'new_user: {e}')
    return {'success': False, 'error_msg': 'Sent data is post request either incomplete or wrong'}

  if mr.rds.sismember(mr.USERNAMES, name):
    return {'success': False, 'error_msg': f'username {name} is already registered'}

  salt = bcrypt.gensalt()
  hashed_password = bcrypt.hashpw(password, salt)
  # To check password: if bcrypt.checkpw(passwd, hashed): print("match")

  mr.rds.sadd(mr.USERNAMES, name)
  mr.rds.hset(mr.USER2PASS, name, hashed_password)
  mr.rds.hset(mr.USER2KEY2E, name, key2_encrypt)

  m_key = generate_mkey()

  mr.rds.hset(mr.MKEY2USER, m_key, name)
  mr.rds.hset(mr.USER2MKEY, name, m_key)

  mr.rds.hset(mr.USER2IP, name, node_ip)

  return {'success': True, 'm_key': m_key}


@app.route('/login_user', methods=['POST'])
def login_user():
  data = request.get_json()
  try:
    name = data.name
    password = data.password
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 0}

  if not mr.rds.sismember(mr.USERNAMES, name):
    return {'success': False, 'err': 1}

  stored_password = mr.rds.hget(mr.USER2PASS, name)
  if not check_password_hash(stored_password, password):
    return {'success': False, 'err': 2}

  m_key = mr.rds.hget(mr.USER2MKEY, name)
  key2_encrypt = mr.rds.hget(mr.USER2KEY2E, name)
  return {'success': True, 'm_key': m_key, 'key2_encrypt': key2_encrypt}


@app.route('/heartbeat', methods=['POST'])
def heartbeat():
  data = request.get_json()
  try:
    mkey = data.mkey
    location = data.location
    timestamp = data.timestamp
  except Exception as e:
    logging.log(e)
    return {'success': False}
  username = mr.rds.hget(mr.MKEY2USER, mkey)
  cur_timestamp = mr.rds.hget(mr.USER2TS, username)

  if timestamp > cur_timestamp:
    mr.rds.hset(mr.USER2LOC, username, location)
    mr.rds.hset(mr.USER2TS, username, timestamp)
  return {
    'success': True
  }


if __name__ == "__main__":
  mr.initialize()
  logging.basicConfig(level=logging.DEBUG)
  app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
