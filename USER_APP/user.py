from datetime import datetime
import json
import logging
from typing import Dict, Any, List

import redis
import requests
import urllib.parse

from USER_APP.config import MASTER_URL
from USER_APP.utils import get_ip_address


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
    if c != len(user.required_keys) - params_len:
      raise UserMismatch
  return user


def create_new_user(username: str, m_key: str, key2_encrypt: str, key2_decrypt: str):
  user = User(username, m_key, key2_encrypt, key2_decrypt)
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
