from __future__ import annotations

import json
import logging
import os
import pickle
import base64

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


@app.route("/login", methods=['GET', 'POST'])
def login(name=''):
  if request.method == 'GET':
    user = User()
    user.load()
    return render_template('login.html', user=user, name=name)
  else:
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
      flash(
        'The user object in local storage is not the same as the one used to log in. Please either remove the local '
        'storage or double-check that the data transferred from the previous device is accurate.')
      return render_template('login.html', user=User())

    return redirect(url_for('profile'))


@app.route('/logout', methods=['POST'])
def logout():
  do_delete = 'off'
  try:
    do_delete = request.form.get('do_delete', 'off')
  except Exception as e:
    err_msg = str(e)
    render_template('error.html', error=err_msg)

  user = User()
  if do_delete == 'on':
    user.delete_rds()
  else:
    user.log_out()

  return redirect('/')


@app.route("/register", methods=['GET', 'POST'])
def register(username=''):
  if request.method == 'GET':
    user = User()
    user.load()
    return render_template('register.html', user=user)
  else:
    try:
      username = request.form.get('username')
      password = request.form.get('password')
    except Exception as e:
      err_msg = str(e)
      render_template('error.html', error=err_msg)

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
  user = User()
  user.load()
  a = user.get_images_for(username)
  err_msg = a[1]
  if err_msg != '':
    render_template('error.html', error=err_msg)
  images_b64 = a[0]
  user2 = User(username=username)
  return render_template('other_profile.html', pronoun=username, user=user2, followers=user2.get_followers(),
                         following=user2.get_following(), image_blob_data=images_b64)


@app.route("/profile")
def profile():
  user = User()
  user.load()
  if not user.is_logged_in():
    flash('You are not logged in. Log in to view profile')
    return render_template('login.html', user=user)
  else:

    # import glob
    # images_b64 = []
    # for img_path in glob.glob(f"{app.config['UPLOAD_FOLDER']}*.jpg"):
    #   # path = '/Users/vishal/Downloads/iitd_things/8th_Sem/col726_numerical_algo/assignment_4/Distributed-instagram/USER_APP/FRONT_END/src/images/IITDlogo.png'
    #   with open(img_path, "rb") as image_file:
    #     data = base64.b64encode(image_file.read()).decode("utf-8")
    #   images_b64.append(data)

    a = user.get_my_images_for()
    err_msg = a[1]
    if err_msg != '':
      render_template('error.html', error=err_msg)

    images_b64 = a[0]
    return render_template('profile.html', pronoun='You', user=user, followers=user.get_followers(),
                           following=user.get_following(), images_blob_data=images_b64)


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

      try:
        nd_ids = response['nearby_nodes']

        # ------------ Encryption ------------
        # https://stackoverflow.com/questions/28426102/python-crypto-rsa-public-private-key-with-large-file
        aes_key = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_EAX)
        with open(file_path, "rb") as image_file:
          data = base64.b64encode(image_file.read())  # .decode("utf-8")
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Now aes_key using encrypt key
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(user.get_key2_encrypt().encode()))
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        encoded_info_dict = {'nonce': cipher.nonce, 'ciphertext': ciphertext, 'tag': tag,
                             'encrypted_aes_key': encrypted_aes_key}

        bytes_obj = pickle.dumps(encoded_info_dict)
        encoded_info = base64.b64encode(bytes_obj).decode('utf-8')

        # Decrypt example: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
        # Decrypt aes_key using rsa and then decrypt image using that aes_key

        file_size = os.path.getsize(file_path)
        os.remove(file_path)

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
          r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'record_image_upload'), data={
            'm_key': user.get_m_key(),
            'image_hash': file_path,
            'target_user': nd_id,
            'timestamp': timestamp,
            'image_size': file_size
          })

          if not response['success']:
            err_msg = response['err']
            logging.debug(f'failed writing on node {nd_url}. error: {err_msg}')
            return redirect(url_for('error.html', error=err_msg))

      except Exception as e:
        err_msg = str(e)
        logging.debug(f'error: {err_msg}')
        return redirect(url_for('error.html', error=err_msg))

      return redirect(url_for('profile'))


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


@app.route('/get_encrypted_image', methods=['GET'])
def get_encrypted_image():
  try:
    image_hash = request.args['image_hash']
  except Exception as e:
    logging.debug(e)
    return {'success': False, 'err': e}

  user = User()
  user.load()
  if user.rds.hexists(user.IMAGE_DATA, key=image_hash):
    return {'success': True, 'encoded_info': user.rds.hget(user.IMAGE_DATA, key=image_hash)}
  else:
    return {'success': False, 'err': 'this image hash not in redis'}


@app.route('/uploads/<name>')
def view_file(name):
  return send_from_directory(app.config["UPLOAD_FOLDER"], name)


@app.route("/")
def index():
  user = User()
  user.load()
  return render_template('front_page.html', user=user)


@app.route('/all_users')
def all_users():
  r = requests.get(url=urllib.parse.urljoin(MASTER_URL, 'all_users'))
  response = r.json()
  all_users = response['users']
  user = User()
  user.load()
  following = user.get_following()
  following_set = set(following)
  not_following = []
  for username in all_users:
    if username not in following_set and username != user.get_username():
      not_following.append(username)
  
  return render_template('explore.html', following=following, not_following=not_following, user=user)


@app.route('/follow/<username>')
def follow_new_user(username):
  user = User()
  user.load()
  r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'send_request'), data={
            'm_key': user.get_m_key(),
            'username2': username
          })
  response = json.loads(r.content)
  if not response['success']:
      flash(response['err'])
      return redirect(url_for('all_users'))
  return redirect(url_for('profile'))


@app.route('/accept_request/<username>')
def accept_user(username):
  user = User()
  user.load()
  r = requests.post(url=urllib.parse.urljoin(MASTER_URL, 'accept_request'), data={
            'm_key': user.get_m_key(),
            'username2': username,
            'key2_decrypt': user.get_key2_decrypt()
          })
  response = json.loads(r.content)
  if not response['success']:
      flash(response['err'])
      return redirect(url_for('profile'))
  return redirect(url_for('profile'))


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  app.add_url_rule(
    "/user_data/<name>", endpoint="view_file", build_only=True
  )
  app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
