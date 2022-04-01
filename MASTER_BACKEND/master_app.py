import logging
from operator import ne
import secrets
import string
import logging
from operator import ne
import secrets
import string

import json
from typing import List

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
import threading

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
  IP2USER = 'ip_to_username'
  USER2LOC = 'username_to_location'
  USER2TS = 'username_to_timestamp'
  IMG2USER_SUFFIX = '_user'

  USER2CLUS = 'username_to_cluster'
  CLUS2USERS_PREFIX = 'cluster_to_usernames'

  USER2FOLLOWERS_SUFFIX = '_followers'
  USER2FOLLOWING_SUFFIX = '_following'
  USER2PENDING_SUFFIX = '_pending'

  USER2_DATASIZE = '_node2_datasize'

  def __init__(self, master_ip):
    self.rds = redis.Redis(decode_responses=True, socket_timeout=5)

  def initialize(self):
    self.rds.flushall()

    # for i in range(NUM_CLUSTERS):
    #   self.rds.sadd(self.CLUS2USERS_PREFIX + str(i), "foo")

  def add_image_to_user(self, username, image_hash, time_of_upload: str):
    # User "username" has uploaded image to her profile
    sorted_set_name = username + self.USER2IMG_SUFFIX
    # self.rds.zadd(sorted_set_name, {str(time_of_upload): image_hash})
    self.rds.sadd(sorted_set_name, image_hash)

  def add_user_to_image(self, username, image_hash):
    # Image is stored at node corresponding to username
    set_name = image_hash + self.IMG2USER_SUFFIX
    self.rds.sadd(set_name, username)

  def inc_node_datasize(self, username: str, datasize: float):
    old = self.rds.hget(name=self.USER2_DATASIZE, key=username)
    if old is None:
      old = 0.0
    self.rds.hset(name=self.USER2_DATASIZE, key=username, value=float(old) + float(datasize))

  def get_node_datasize(self, username: str) -> float:
    v = self.rds.hget(name=self.USER2_DATASIZE, key=username)
    if v is None:
      v = 0.0
    return float(v)

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
    location = data['location']
  except Exception as e:
    print(f'new_user: {e}')
    return {'success': False, 'err': 'Sent data is post request either incomplete or wrong'}

  if mr.rds.sismember(mr.USERNAMES, name):
    return {'success': False, 'err': f'username {name} is already registered'}

  salt = bcrypt.gensalt()
  hashed_password = bcrypt.hashpw(password.encode(), salt)
  # To check password: if bcrypt.checkpw(passwd, hashed): print("match")

  mr.rds.sadd(mr.USERNAMES, name)
  mr.rds.hset(mr.USER2PASS, name, hashed_password)
  mr.rds.hset(mr.USER2KEY2E, name, key2_encrypt)
  mr.rds.hset(mr.USER2LOC, name, location)

  m_key = generate_mkey(name)

  mr.rds.hset(mr.MKEY2USER, m_key, name)
  mr.rds.hset(mr.USER2MKEY, name, m_key)

  mr.rds.hset(mr.USER2IP, name, node_ip)
  mr.rds.hset(mr.IP2USER, node_ip, name)

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
    return {'success': False, 'err': 'data sent is incomplete'}

  username = mr.rds.hget(mr.MKEY2USER, mkey)
  if not mr.rds.hexists(mr.USER2TS, username) or int(timestamp) > int(mr.rds.hget(mr.USER2TS, username)):
    mr.rds.hset(mr.USER2LOC, username, location)
    mr.rds.hset(mr.USER2TS, username, timestamp)
  return {'success': True}


@app.route('/followers')
def followers():
  if 'name' not in request.args:
    return {'success': False, 'err': 'data sent is incomplete'}
  name = request.args['name']
  set_name = name + mr.USER2FOLLOWERS_SUFFIX
  return {'success': True, 'followers': list(mr.rds.smembers(set_name))}


@app.route('/following', methods=['GET'])
def following():
  if 'name' not in request.args:
    return {'success': False, 'err': 'data sent is incomplete'}
  name = request.args['name']
  set_name = name + mr.USER2FOLLOWING_SUFFIX
  return {'success': True, 'following': list(mr.rds.smembers(set_name))}


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
  return {'success': True, 'pending_requests': list(mr.rds.smembers(set_name))}


@app.route('/get_username_from_ip', methods=['GET'])
def get_username_from_ip():
  try:
    node_ip = request.args['node_ip']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': str(e)}

  username = mr.rds.hget(mr.IP2USER, node_ip)
  return {'success': True, 'username': username}


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

  node_ip = mr.rds.hget(mr.USER2IP, username2)
  print(f'sending decrypt key to {node_ip}')
  r: requests.models.Response = requests.post(url=urllib.parse.urljoin(get_node_url(node_ip), 'store_key2_decrypt'),
                                              data={
                                                'username': username,
                                                'key2_decrypt': key2_decrypt
                                              })

  try:
    response = json.loads(r.content)
    if not response['success']:
      return {'success': False, 'err': str(response['err'])}
    return {'success': True}
  except Exception as e:
    # TODO: make this fault-tolerant
    logging.debug(str(e))
    return {'success': False, 'err': str(e)}


@app.route('/send_request', methods=['POST'])
def send_request():
  data = request.form
  try:
    m_key = data['m_key']  # to identify the user
    username2 = data['username2']  # to whom the user wants to follow
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 'data sent is incomplete'}

  username = mr.rds.hget(mr.MKEY2USER, m_key)
  mr.add_follow_request(username, username2)
  return {'success': True}


@app.route('/nearby_nodes', methods=['GET'])
def get_nearby_nodes():
  """returns list[str]: list of usernames where image should be stored"""
  # return {'nearby_nodes': ['10.17.51.108']}
  if 'name' not in request.args:
    return {'success': False, 'nearby_nodes': [], 'err': 'name not sent'}

  username = request.args['name']
  all_clusters = mr.rds.hgetall(mr.USER2CLUS)
  clusters_added = set()

  # Picking from user own cluster. This will help reduce the latency for user and its followers assuming they are in
  # same cluster
  cluster = mr.rds.hget(mr.USER2CLUS, username)
  users_in_cluster: List[str] = list(mr.rds.smembers(mr.CLUS2USERS_PREFIX + str(cluster)))
  nearby_nodes = []

  users_in_cluster.remove(username)
  users_in_cluster.sort(key=lambda name: mr.get_node_datasize(name))

  # Pick NUM_REPLICATIONS // 2 elements from users_in_cluster
  nearby_nodes += users_in_cluster[:NUM_REPLICATIONS // 2]
  clusters_added.add(int(cluster))

  # max_tries will enable to loop to terminate in case there are not enough clusters
  max_tries = 0
  while len(nearby_nodes) < NUM_REPLICATIONS:
    if max_tries > 20:
      break
    # Pick a random cluster not already added
    ind = random.randint(0, NUM_CLUSTERS - 1)
    if ind not in clusters_added:
      users_in_cluster_temp = list(mr.rds.smembers(mr.CLUS2USERS_PREFIX + str(ind)))
      nd = min(users_in_cluster_temp, key=lambda name: mr.get_node_datasize(name))
      nearby_nodes.append(nd)
      clusters_added.add(ind)
    max_tries += 1

  return {'success': True, 'nearby_nodes': nearby_nodes}


@app.route('/reset_following', methods=['POST'])
def reset_following():
  try:
    m_key = request.form['m_key']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 0}

  # TODO (bindal): Set following of username = []
  pass


@app.route('/get_username_ip', methods=['GET'])
def get_username_ip():
  if 'name' not in request.args:
    return {'success': False, 'err': 'name not sent'}
  username = request.args['name']
  return {'success': True, 'node_ip': mr.rds.hget(mr.USER2IP, username)}


@app.route('/get_images', methods=['GET'])
def get_images():
  if 'name' not in request.args:
    return {'success': False, 'err': 'name not sent'}
  username = request.args['name']
  set_name = username + mr.USER2IMG_SUFFIX
  all_images = mr.rds.smembers(set_name)
  return {'success': True, 'images': list(all_images)}


@app.route('/get_node_for_image', methods=['POST'])
def get_node_for_image():
  try:
    m_key = request.form['m_key']
    image_hash = request.form['image_hash']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 0}

  username = mr.rds.hget(mr.MKEY2USER, m_key)  # User wanting the image
  image_owner_set = image_hash + mr.IMG2USER_SUFFIX  # Name of set of users containing the image

  target_name = None  # target username from which file should be accessed

  cluster = mr.rds.hget(mr.USER2CLUS, username)
  owners_ips = list(mr.rds.smembers(image_owner_set))

  owners_ips_sorted = []
  for owner_ip in owners_ips:
    owner_name = mr.rds.hget(mr.IP2USER, owner_ip)
    if mr.rds.hget(mr.USER2CLUS, owner_name) == cluster:
      owners_ips_sorted.append(owner_ip)

  for owner_ip in owners_ips:
    owner_name = mr.rds.hget(mr.IP2USER, owner_ip)
    if mr.rds.hget(mr.USER2CLUS, owner_name) != cluster:
      owners_ips_sorted.append(owner_ip)

  # owners_sorted contains users ips from own cluster first
  for node_ip in owners_ips_sorted:
    try:
      r = requests.get(url=urllib.parse.urljoin(get_node_url(node_ip), 'ping'))
      response = r.json()
      if not response['success']:
        pass
      target_name = node_ip
      break
    except Exception as e:
      logging.debug(e)
      pass

  if target_name is None:
    return {'success': False, 'err': 'No owner online'}
  else:
    return {'success': True, 'node_ip': target_name}


@app.route('/record_image_upload', methods=['POST'])
def record_image_upload():
  data = request.form
  try:
    m_key = data['m_key']
    image_hash = data['image_hash']
    target_user_ip = data['target_user']
    timestamp = data['timestamp']
    image_size = data['image_size']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': 'data sent is incomplete'}

  username = mr.rds.hget(mr.MKEY2USER, m_key)
  mr.add_image_to_user(username, image_hash, timestamp)
  mr.add_user_to_image(target_user_ip, image_hash)
  target_username = mr.rds.hget(mr.IP2USER, target_user_ip)
  mr.inc_node_datasize(target_username, float(image_size))
  return {'success': True}


@app.route('/all_users')
def all_users():
  users = mr.rds.smembers(mr.USERNAMES)
  return {'success': True, 'users': list(users)}


if __name__ == "__main__":
  # mr.initialize()
  logging.basicConfig(level=logging.DEBUG)
  app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
