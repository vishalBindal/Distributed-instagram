from __future__ import annotations

import json
import logging
import os
import pickle

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from flask import redirect, url_for, render_template, request, flash, send_from_directory
from datetime import datetime
import requests
from werkzeug.utils import secure_filename

from user import User, log_user_in, UserMismatch, create_new_user
from utils import get_ip_address, generate_key_pair, allowed_file
from config import MASTER_URL, app
from pathlib import Path
import urllib.parse


# TODO: Make all imp post request in celery to keep trying again


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
    flash(response['err'])
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
  user2 = User(username=username)

  return render_template('other_profile.html', pronoun=username, user=user2, followers=user2.get_followers(),
                         following=user2.get_following(), image_blob_data=['fwefwfwefwefwefwe'])


@app.route("/profile")
def profile():
  user = User()
  user.load()
  if not user.is_logged_in():
    flash('You are not logged in. Log in to view profile')
    return render_template('login.html', user=user)
  else:
    data = open(
      '/Users/vishal/Downloads/iitd_things/8th_Sem/col726_numerical_algo/assignment_4/Distributed-instagram/USER_APP/FRONT_END/src/images/IITDlogo.png',
      'rb').read()
    return render_template('profile.html', pronoun='You', user=user, followers=user.get_followers(),
                           following=user.get_following(), images_blob_data=[data])


@app.route("/")
def index():
  user = User()
  user.load()
  return render_template('front_page.html', user=user)


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

      dir_path = app.config['UPLOAD_FOLDER']
      Path(dir_path).mkdir(parents=True, exist_ok=True)

      file_path = os.path.join(dir_path, filename)
      file.save(file_path)

      # Process File
      # TODO: Do this asyncly on celery
      r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'nearby_nodes'),
                       params={'node_ip': user.get_user_ip_address()})
      response = r.json()

      # TODO: check if file is actually bytes o.w load from filepath
      try:
        nd_ids = response['nearby_nodes']

        # https://stackoverflow.com/questions/28426102/python-crypto-rsa-public-private-key-with-large-file
        aes_key = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_EAX)
        data = open(file_path, 'rb').read()
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
            'unique_hash': file_path,
            'encoded_info': encoded_info
          })
          response = json.loads(r.content)

          if not response['success']:
            err_msg = response['err']
            logging.debug(f'failed writing on node {nd_url}. error: {err_msg}')
            return redirect(url_for('error.html', error=err_msg))

          curr_dt = datetime.now()
          timestamp = int(round(curr_dt.timestamp()))
          r = requests.post(url=urllib.parse.urljoin(nd_url, 'record_image_upload'), data={
            'm_key': user.get_m_key(),
            'image_hash': file_path,
            'target_user': nd_id,
            'timestamp': timestamp
          })

          if not response['success']:
            err_msg = response['err']
            logging.debug(f'failed writing on node {nd_url}. error: {err_msg}')
            return redirect(url_for('error.html', error=err_msg))

      except Exception as e:
        err_msg = str(e)
        logging.debug(f'error: {err_msg}')
        return redirect(url_for('error.html', error=err_msg))

      return redirect(url_for('download_file', name=filename))


@app.route('/add_image_data', methods=['POST'])
def add_image_data():
  data = request.form
  try:
    unique_hash = data['unique_hash']
    encoded_info = data['encoded_info']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': e}
  user = User()
  user.load()
  # if not user.is_logged_in():
  #   return {'success': False, 'err': 'user is not logged in on this node'}
  # else:
  user.add_image_data(unique_hash=unique_hash, encoded_info=encoded_info)
  return {'success': True}


@app.route('/uploads/<name>')
def download_file(name):
  return send_from_directory(app.config["UPLOAD_FOLDER"], name)


def send_heartbeat():
  while True:
    user = User()
    user.load()
    if not user.is_logged_in():
      flash('You are not logged in. Log in to view dashboard')
      return render_template('login.html', user=user)
    else:  
      curr_dt = datetime.now()
      timestamp = int(round(curr_dt.timestamp()))
      import random
      x, y = random.randint(0,100), random.randint(0,100)
      location=f"{x},{y}"
      r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'heartbeat'), data={
        'm_key': user.get_m_key(),
        'location': location,
        'timestamp': timestamp
      })
    from time import sleep
    sleep(60.)


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  app.add_url_rule(
    "/user_data/<name>", endpoint="download_file", build_only=True
  )
  import threading
  t = threading.Thread(target=send_heartbeat)
  t.start()
  app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
