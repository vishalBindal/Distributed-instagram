import os
import socket
from typing import Tuple

from redis import Redis
from flask import flash, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename


import requests
import datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

def get_ip_address():
  hostname = socket.gethostname()  # baadalvm
  ip_address = socket.gethostbyname(hostname)  # Private IP of Node
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

key2_encrypt, key2_decrypt = generate_key_pair()

original = open('/Users/vishal/Downloads/iitd_things/8th_Sem/col726_numerical_algo/assignment_4/Distributed-instagram/IITDlogo.png', 'rb').read()

cipher_rsa = PKCS1_OAEP.new(RSA.import_key(key2_encrypt.encode()))
encrypted = cipher_rsa.encrypt(original)

cipher_rsa = PKCS1_OAEP.new(RSA.import_key(key2_decrypt.encode()))
decrypted = cipher_rsa.decrypt(encrypted, key2_decrypt)

with open('/Users/vishal/Downloads/iitd_things/8th_Sem/col726_numerical_algo/assignment_4/Distributed-instagram/decrypted.png', 'wb') as decrypted_file:
    decrypted_file.write(decrypted)

