import logging
from operator import ne
import secrets
import string
import logging
from operator import ne
import secrets
import string

import json
from flask import Flask, redirect, url_for, render_template, request, flash, send_from_directory
from datetime import date, datetime

import redis
from abc import ABC

from config import MASTER_IP, NUM_CLUSTERS, NUM_REPLICATIONS
import bcrypt
import time
import requests
import urllib.parse
from utils import get_node_url
import random

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

  USER2CLUS = 'username_to_cluster'
  CLUS2USERS_PREFIX = 'cluster_to_usernames'

  USER2FOLLOWERS_SUFFIX = '_followers'
  USER2FOLLOWING_SUFFIX = '_following'
  USER2PENDING_SUFFIX = '_pending'

  def __init__(self, master_ip):
    self.rds = redis.Redis(decode_responses=True, socket_timeout=5)

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

    # setup USER2CLUS
    self.rds.hset(self.USER2CLUS, "foo", "foo")

    for i in range(NUM_CLUSTERS):
      self.rds.sadd(self.CLUS2USERS_PREFIX + str(i), "foo")

    # Setup USER2IP
    self.rds.hset(self.USER2IP, "foo", "foo")
    # Setup USER2LOC
    self.rds.hset(self.USER2LOC, "foo", "foo")
    # Setup USER2TS
    self.rds.hset(self.USER2TS, "foo", "foo")

  def add_image_to_user(self, username, image_hash, time_of_upload: str):
    # User "username" has uploaded image to her profile
    sorted_set_name = username + self.USER2IMG_SUFFIX
    self.rds.zadd(sorted_set_name, {str(time_of_upload): image_hash})

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


def generate_mkey(username):
  # generating random string of length 512
  key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(512))
  return key + username


@app.route('/new_user', methods=['POST'])
def new_user():
  data = request.form
  try:
    name = data['name']
    password = data['password']
    key2_encrypt = data['key2_encrypt']
    node_ip = data['node_ip']
  except Exception as e:
    print(f'new_user: {e}')
    return {'success': False, 'error_msg': 'Sent data is post request either incomplete or wrong'}

  if mr.rds.sismember(mr.USERNAMES, name):
    return {'success': False, 'error_msg': f'username {name} is already registered'}

  salt = bcrypt.gensalt()
  hashed_password = bcrypt.hashpw(password.encode(), salt)
  # To check password: if bcrypt.checkpw(passwd, hashed): print("match")

  mr.rds.sadd(mr.USERNAMES, name)
  mr.rds.hset(mr.USER2PASS, name, hashed_password)
  mr.rds.hset(mr.USER2KEY2E, name, key2_encrypt)

  m_key = generate_mkey(name)

  mr.rds.hset(mr.MKEY2USER, m_key, name)
  mr.rds.hset(mr.USER2MKEY, name, m_key)

  mr.rds.hset(mr.USER2IP, name, node_ip)

  return {'success': True, 'm_key': m_key}


@app.route('/login_user', methods=['POST'])
def login_user():
  data = request.form
  try:
    name = data['name']
    password = data['password']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': str(e)}

  if not mr.rds.sismember(mr.USERNAMES, name):
    return {'success': False, 'err': f'no user {name}'}

  hashed_password = mr.rds.hget(mr.USER2PASS, name)
  if not bcrypt.checkpw(password.encode(), hashed_password.encode()):
    return {'success': False, 'err': 'password didn\'t match'}

  m_key = mr.rds.hget(mr.USER2MKEY, name)
  key2_encrypt = mr.rds.hget(mr.USER2KEY2E, name)
  return {'success': True, 'm_key': m_key, 'key2_encrypt': key2_encrypt}


@app.route('/heartbeat', methods=['POST'])
def heartbeat():
  data = request.form
  try:
    mkey = data['m_key']
    location = data['location']
    timestamp = data['timestamp']
  except Exception as e:
    logging.debug(e)
    return {'success': False}

  username = mr.rds.hget(mr.MKEY2USER, mkey)
  if not mr.rds.hexists(mr.USER2TS, username) or int(timestamp) > int(mr.rds.hget(mr.USER2TS, username)):
    mr.rds.hset(mr.USER2LOC, username, location)
    mr.rds.hset(mr.USER2TS, username, timestamp)
  return {
    'success': True
  }


@app.route('/followers')
def followers():
  name = request.args['name']
  set_name = name + mr.USER2FOLLOWERS_SUFFIX
  try:
    followers = mr.rds.smembers(set_name)
    return {
      'followers': list(followers)
    }
  except:
    return {
      'followers': []
    }


@app.route('/following')
def following():
  name = request.args['name']
  set_name = name + mr.USER2FOLLOWING_SUFFIX
  try:
    following = mr.rds.smembers(set_name)
    return {
      'following': list(following)
    }
  except:
    return {
      'following': []
    }


@app.route('/pending_requests', methods=['POST'])
def pending_requests():
  data = request.form
  try:
    m_key = data['m_key']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 0}

  name = mr.rds.hget(mr.MKEY2USER, m_key)
  set_name = name + mr.USER2PENDING_SUFFIX
  try:
    pending_requests = mr.rds.smembers(set_name)
    return {
      'pending_requests': list(pending_requests)
    }
  except:
    return {
      'pending_requests': []
    }


@app.route('/accept_request', methods=['POST'])
def accept_request():
  data = request.form
  try:
    m_key = data['m_key']
    username2 = data['username2']
    key2_decrypt = data['key2_decrypt']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 0}

  username = mr.rds.hget(mr.MKEY2USER, m_key)
  mr.accept_follow_request(username2, username)

  node_ip = mr.rds.hget(mr.USER2IP, username)
  r: requests.models.Response = requests.post(url=urllib.parse.urljoin(get_node_url(node_ip), 'get_key2_decrypt'), data={
    'username': username,
    'key2_decrypt': key2_decrypt
  })

  try:
    response = json.loads(r.content)
    if not response['success']:
      pass
  except:
    pass
  # TODO: make the above fault-tolerant

  return {
    'success': True
  }


@app.route('/send_request', methods=['POST'])
def send_request():
  data = request.form
  try:
    m_key = data['m_key']  # to identify the user
    username2 = data['username2']  # to whom the user wants to follow
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 0}

  username = mr.rds.hget(mr.MKEY2USER, m_key)
  mr.add_follow_request(username, username2)
  return {
    'success': True
  }


@app.route('/nearby_nodes', methods=['GET'])
def get_nearby_nodes():
  return {'nearby_nodes': ['10.17.51.108']}
  # TODO (chirag): Check this function
  username = request.args['name']
  try:
    cluster = mr.rds.hget(mr.USER2CLUS, username)
    users_in_cluster = list(mr.rds.smembers(mr.CLUS2USERS_PREFIX + str(cluster)))
    nearby_nodes = []
    clusters_added = set()
    clusters_added.add(cluster)

    while len(nearby_nodes) < NUM_REPLICATIONS // 5:
      ind = random.randint(a=0, b=10000) % len(users_in_cluster)
      if users_in_cluster[ind] not in nearby_nodes and users_in_cluster[ind] != username:
        nearby_nodes.append(users_in_cluster[ind])

    while len(nearby_nodes) < NUM_REPLICATIONS:
      ind = random.randint(a=0, b=10000) % NUM_CLUSTERS
      if ind not in clusters_added:
        users_in_cluster_temp = list(mr.rds.smembers(mr.CLUS2USERS_PREFIX + str(cluster)))
        ind1 = random.randint(a=0, b=10000) % len(users_in_cluster_temp)
        nearby_nodes.append(users_in_cluster_temp[ind])
        clusters_added.add(ind)

    return {'nearby_nodes': nearby_nodes}

  except Exception as e:
    return {'nearby_nodes': []}

  # Return list[str]: list of usernames where image should be stored


@app.route('/get_images')
def get_images():
  username = request.args['name']
  set_name = username + mr.USER2IMG_SUFFIX
  all_images = mr.rds.smembers(set_name)
  return {
    'images': list(all_images)
  }


@app.route('/get_node_for_image', methods=['POST'])
def get_node_for_image():
  data = request.form
  try:
    m_key = data['m_key']
    image_hash = data['image_hash']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 0}

  username = mr.rds.hget(mr.MKEY2USER, m_key)  # User wanting the image
  image_owner_set = image_hash + mr.IMG2USER_SUFFIX  # Name of set of users containing the image

  targetname = None  # target username from which file should be accessed

  cluster = mr.rds.hget(mr.USER2CLUS, username)
  owners = list(mr.rds.smembers(image_owner_set))

  for owner in owners:
    if (mr.rds.hget(mr.USER2CLUS, owner) == cluster):
      targetname = owner
      break

  targetname = mr.rds.hget(mr.USER2IP, targetname)
  if (targetname == None):
    targetname = owners[0]

  return {
    'success': True,
    'node_ip': targetname
  }


@app.route('/record_image_upload', methods=['POST'])
def record_image_upload():
  data = request.form
  try:
    m_key = data['m_key']
    image_hash = data['image_hash']
    target_user = data['target_user']
    timestamp = data['timestamp']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 0}

  username = mr.rds.hget(mr.MKEY2USER, m_key)
  mr.add_image_to_user(username, image_hash, timestamp)
  mr.add_user_to_image(target_user, image_hash)


if __name__ == "__main__":
  mr.initialize()

  logging.basicConfig(level=logging.DEBUG)
  app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
