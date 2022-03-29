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


def get_ip_address():
  hostname = socket.gethostname()  # baadalvm
  ip_address = socket.gethostbyname(hostname)  # Private IP of Node
  return ip_address


def allowed_file(filename: str):
  return '.' in filename and \
         filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_key_pair() -> Tuple[bytes, bytes]:
  """returns a public key and private key"""
  key = RSA.generate(2048)
  p_key = key.publickey().exportKey('PEM')
  private_key = key.exportKey('PEM')
  return p_key, private_key


@app.route('/upload_pic', methods=['GET', 'POST'])
def upload_pic():
  if request.method == 'POST':
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
      filename_prefix = str(datetime.datetime.now().date()) + '_' + \
                        str(datetime.datetime.now().time()).replace(':', '.') + str(current_username)
      filename = filename_prefix + secure_filename(file.filename)
      file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

      # Process File
      # TODO: Do this asyncly on celery
      r = requests.post(url=MASTER_IP, data={'my_ip': my_ip})
      response = r.text
      try:
        nd_ids = dict(response)
        e_blog_data = encrypt(data=file, using=key2_encypt)
        for no_id in nd_ids:
          rds: Redis = get_rds_connection(no_id)  # self.conns[i]
          n = rds.hset(name='images', key=filename, value=e_blog_data)
          assert n == 1
      except Exception as e:
        print(e)
        return e

      return redirect(url_for('download_file', name=filename))
  return '''
    <!doctype html>
    <title>Upload new Image</title>
    <h1>Upload new Image</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''


@app.route('/uploads/<name>')
def download_file(name):
  return send_from_directory(app.config["UPLOAD_FOLDER"], name)


app.add_url_rule(
  "/user_data/<name>", endpoint="download_file", build_only=True
)

if __name__ == "__main__":
  # if not first time then remove this
  app.run(debug=True, port=8000)
