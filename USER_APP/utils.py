import os
import socket
from typing import Tuple

from redis import Redis
from flask import flash, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from config import ALLOWED_EXTENSIONS, app, MASTER_IP
import requests
import datetime
from Cryptodome.PublicKey import RSA
import netifaces


def get_ip_address():
  # TODO: try to fix this
  hostname = socket.gethostname()  # baadalvm
  ip_address = socket.gethostbyname(hostname)  # Private IP of Node
  if ip_address.startswith('127'):

    # for interface in netifaces.interfaces():
    addrs = netifaces.ifaddresses('en0')
    ip = addrs[netifaces.AF_INET][0]['addr']
    return ip

  else:
    return ip_address

def allowed_file(filename: str):
  return '.' in filename and \
         filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_key_pair() -> Tuple[str, str]:
  """returns a public key and private key"""
  key = RSA.generate(2048)
  p_key = key.publickey().exportKey('PEM')
  private_key = key.exportKey('PEM')
  return p_key.decode(), private_key.decode()
