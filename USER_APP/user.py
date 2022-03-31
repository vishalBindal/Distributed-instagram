import base64
import pickle
from datetime import datetime
import json
import logging
from typing import Dict, Any, List, Tuple

import redis
import requests
import urllib.parse

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA

from config import MASTER_URL
from utils import get_ip_address


class UserMismatch(Exception):
  pass


class User:
  USER_DATA_KEY = 'user_data'
  DECRYPT_FOLLOWING_KEY = 'decrypt_following_key'
  required_keys = ['username', 'm_key', 'key2_encrypt', 'key2_decrypt', 'creation_time']
  IMAGE_DATA = 'image_data'

  def __init__(self, username: str = '', m_key: str = '', key2_encrypt: str = '', key2_decrypt: str = ''):
    self.loaded = False
    self.rds = redis.Redis(decode_responses=True, socket_timeout=5)
    self.rds_no_decode = redis.Redis(decode_responses=False, socket_timeout=5)
    self.user_data: Dict[str, Any] = {'logged_in': 0, 'username': username, 'm_key': m_key, 'key2_encrypt': key2_encrypt,
                                      'key2_decrypt': key2_decrypt, 'creation_time': self.get_current_time_str()}
    self.key2_decrypt_following: Dict[str, str] = dict()

  def get_username(self):
    return self.user_data['username']

  def get_m_key(self):
    return self.user_data['m_key']

  def get_key2_encrypt(self):
    return self.user_data['key2_encrypt']

  def get_key2_decrypt(self):
    return self.user_data['key2_decrypt']

  def get_creation_time(self) -> str:
    return self.user_data['creation_time']

  def store_key_2decrypt(self, username2: str, key2_decrypt: str):
    self.key2_decrypt_following[username2] = key2_decrypt
    self.rds.hset(self.DECRYPT_FOLLOWING_KEY, key=username2, value=key2_decrypt)
    self.save()

  def add_following(self, username2: str, following_decrypt_key: str):
    """This function will be called after someone accepts your follow request. That person who accept will send decrypt
    key to master and master will send it to you through a post request and then this function will be called."""
    self.key2_decrypt_following[username2] = following_decrypt_key
    self.rds.hset(name=self.DECRYPT_FOLLOWING_KEY, key=username2, value=following_decrypt_key)

  def is_logged_in(self) -> bool:
    return int(self.user_data['logged_in']) > 0

  @staticmethod
  def get_user_ip_address():
    return get_ip_address()

  def get_followers(self):
    return get_followers(self.get_username())

  def get_following(self):
    return get_following(self.get_username())

  def get_pending_requests(self):
    r: requests.models.Response = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'pending_requests'),
                                                data={'m_key': self.get_m_key()})

    data = json.loads(r.content)
    pending_requests: List[str] = data['pending_requests']
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
    # for key in self.user_data:
    #   if self.user_data[key] == '':
    #     raise Exception('Can\'t save. The local object is not populated fully.')
    self.rds.hmset(name=self.USER_DATA_KEY, mapping=self.user_data)
    if len(self.key2_decrypt_following) > 0:
      self.rds.hmset(name=self.DECRYPT_FOLLOWING_KEY, mapping=self.key2_decrypt_following)

  @staticmethod
  def get_current_time_str() -> str:
    # dd/mm/YY H:M:S
    dt = datetime.now()
    dt_string = dt.strftime("%d/%m/%Y %H:%M:%S")
    return dt_string

  def log_out(self):
    self.load()
    self.user_data['logged_in'] = 0
    self.save()

  def delete_rds(self):
    self.rds.delete(self.USER_DATA_KEY)

  def try_recovery(self):
    # TODO: Do this recovery in celery so as to make it fault tolerant
    # If master is down user keeps trying through celery task

    # ------ put this inside celery task and starts async ------
    r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'reset_following'), data={'m_key': self.user_data['m_key']})
    # Following will be empty since I don't have any ones key2_decrypt. So, you will need to follow everyone again

    # TODO (bindal): Complete this request
    r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'get_decrypt_key_from_follower'),
                      data={'m_key': self.user_data['m_key']})
    res = json.loads(r.content)

    if not res['success']:
      logging.debug('try again')
      # TODO: Send request to recover key2_decrypt from followers asynchronously
      # Keep trying to recover for some time (Say 5 minutes for the purpose of this assignment)
      # But is it safe to ask for decrypt key ?

    self.user_data['key2_decrypt'] = res['key2_decrypt']
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

  def get_my_images_for(self) -> Tuple[List[str], str]:
    r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'get_images'), params={'name': self.get_username()})
    image_hashes = r.json()['images']

    images_b64 = []
    for image_hash in image_hashes:
      r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'get_node_for_image'), data={
        'm_key': self.get_m_key(),
        'image_hash': image_hash
      })
      response = json.loads(r.content)
      if not response['success']:
        logging.error(response['err'])
        return [], response['err']
      node_ip = response['node_ip']

      if self.get_key2_decrypt() == '':
        err_msg = 'you don\'t have your own decrypt key'
        logging.debug(err_msg)
        return [], err_msg

      node_url = f'http://{node_ip}:8000'
      r = requests.get(url=urllib.parse.urljoin(node_url, 'get_encrypted_image'), params={
        'image_hash': image_hash
      }, headers={'Content-Type': 'application/octet-stream'})

      encoded_info = base64.b64decode(r.json()['encoded_info'])

      encoded_info_dict = pickle.loads(encoded_info)

      cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.get_key2_decrypt()))
      aes_key = cipher_rsa.decrypt(encoded_info_dict['encrypted_aes_key'])

      nonce, tag, ciphertext = encoded_info_dict['nonce'], encoded_info_dict['tag'], encoded_info_dict['ciphertext']
      cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
      data = cipher.decrypt_and_verify(ciphertext, tag)
      images_b64.append(data.decode('utf-8'))
    return images_b64, ''

  def get_images_for(self, following: str) -> Tuple[List[str], str]:
    r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'get_images'), params={'name': following})
    image_hashes = r.json()['images']

    images_b64 = []
    for image_hash in image_hashes:
      r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'get_node_for_image'), data={
        'm_key': self.get_m_key(),
        'image_hash': image_hash
      })
      response = json.loads(r.content)
      if not response['success']:
        logging.error(response['err'])
        return [], response['err']
      node_ip = response['node_ip']

      if node_ip not in self.key2_decrypt_following:
        err_msg = 'you are not following this user'
        logging.debug(err_msg)
        return [], err_msg

      node_url = f'http://{node_ip}:8000'
      r = requests.get(url=urllib.parse.urljoin(node_url, 'get_encrypted_image'), params={
        'image_hash': image_hash
      }, headers={'Content-Type': 'application/octet-stream'})

      encoded_info = base64.b64decode(r.json()['encoded_info'])

      encoded_info_dict = pickle.loads(encoded_info)

      cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.key2_decrypt_following[node_ip].encode()))
      aes_key = cipher_rsa.decrypt(encoded_info_dict['encrypted_aes_key'])

      nonce, tag, ciphertext = encoded_info_dict['nonce'], encoded_info_dict['tag'], encoded_info_dict['ciphertext']
      cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
      data = cipher.decrypt_and_verify(ciphertext, tag)
      images_b64.append(data.decode('utf-8'))
    return images_b64, ''


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
    if c != len(user.required_keys) - params_len:
      raise UserMismatch

  user.user_data['logged_in'] = 1
  user.save()
  return user


def create_new_user(username: str, m_key: str, key2_encrypt: str, key2_decrypt: str):
  user = User(username, m_key, key2_encrypt, key2_decrypt)
  user.user_data['logged_in'] = 1
  user.save()


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
