import base64
import os
import pickle
from typing import Tuple

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import time


# https://stackoverflow.com/questions/28426102/python-crypto-rsa-public-private-key-with-large-file

def generate_key_pair() -> Tuple[str, str]:
  """returns a public key and private key"""
  key = RSA.generate(2048)
  p_key = key.publickey().exportKey('PEM')
  private_key = key.exportKey('PEM')
  return p_key.decode(), private_key.decode()


def encode(file_path, key2_encrypt):
  aes_key = get_random_bytes(16)
  cipher = AES.new(aes_key, AES.MODE_EAX)
  with open(file_path, "rb") as image_file:
    data = base64.b64encode(image_file.read())  # .decode("utf-8")
  ciphertext, tag = cipher.encrypt_and_digest(data)

  # Now aes_key using encrypt key
  cipher_rsa = PKCS1_OAEP.new(RSA.import_key(key2_encrypt.encode()))
  encrypted_aes_key = cipher_rsa.encrypt(aes_key)

  encoded_info_dict = {'nonce': cipher.nonce, 'ciphertext': ciphertext, 'tag': tag,
                       'encrypted_aes_key': encrypted_aes_key}


import glob
key2_encrypt, key2_decrypt = generate_key_pair()
for filename in glob.glob(
        '/Users/vishal/Downloads/iitd_things/8th_Sem/col726_numerical_algo/assignment_4/del sizes/*.jpeg'):
  start_time = time.time()
  file_size = os.stat(filename)
  print(file_size.st_size / (1024 * 1024))
  encode(file_path=filename, key2_encrypt=key2_encrypt)
  print("--- %s seconds ---" % (time.time() - start_time))
