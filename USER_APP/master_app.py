import secrets
import string

from flask import Flask, redirect, url_for, render_template, request, flash, json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime
import redis
from abc import ABC
from config import MASTER_IP
import bcrypt
import time

app = Flask(__name__, static_url_path='/FRONT_END/src', static_folder='FRONT_END/src', template_folder='FRONT_END')
app.config['SECRET_KEY'] = 'we are the champions'


class MasterRedis(ABC):
    USERNAMES = 'usernames'
    USER2PASS = 'username_to_password'
    USER2KEY2E = 'username_to_key2_encrypt'
    MKEY2USER = 'm_key_to_username'
    USER2MKEY = 'username_to_m_key'
    USER2IMG_SUFFIX = '_img'

    NODES = 'nodes'
    NODE2LOC = 'node-id_to_location'
    NODE2TS = 'node-id_to_timestamp'
    IMG2NODE_SUFFIX = '_node'

    def __init__(self, master_ip):
        self.rds = redis.Redis(host=master_ip, decode_responses=True, socket_timeout=5)

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

        # Setup NODES
        self.rds.sadd(self.NODES, "foo")
        # Setup NODE2LOC
        self.rds.hset(self.NODE2LOC, "foo", "foo")
        # Setup NODE2TS
        self.rds.hset(self.NOE2TS, "foo", "foo")

    def add_image_to_user(self, username, image_hash, time_of_upload):
        # add image_hash to username's sorted set
        sorted_set_name = username + self.USER_IMG_SUFFIX
        self.rds.zadd(sorted_set_name, {image_hash, time_of_upload})

    def add_node_to_image(self, node_id, image_hash):
        set_name = image_hash + self.IMG2NODE_SUFFIX
        self.rds.sadd(set_name, node_id)


mr = MasterRedis(MASTER_IP)


def get_master_rds():
    return MasterRedis(MASTER_IP)


def generate_mkey():
    # generating random string of length 512
    key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(512))
    return key


@app.route('/new_user', methods=['POST'])
def new_user():
    data = request.get_json()
    try:
        name = data.name
        password = data.password
        key2_encrypt = data.key2_encrypt
        node_ip = data.node_ip
    except Exception as e:
        print(f'new_user: {e}')
        return {'success': False, 'error_msg': 'Sent data is post request either incomplete or wrong'}

    if mr.rds.sismember(mr.USERNAMES, name):
        return {'success': False, 'error_msg': f'username {name} is already registered'}

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password, salt)
    # To check password: if bcrypt.checkpw(passwd, hashed): print("match")

    mr.rds.sadd(mr.USERNAMES, name)
    mr.rds.hset(mr.USER2PASS, name, hashed_password)
    mr.rds.hset(mr.USER2KEY2E, name, key2_encrypt)

    m_key = generate_mkey()

    mr.rds.hset(mr.MKEY2USER, m_key, name)
    mr.rds.hset(mr.USER2MKEY, name, m_key)

    mr.rds.sadd(mr.NODES, node_ip)

    return {'success': True, 'm_key': m_key}


@app.route('/login_user', methods=['POST'])
def login_user():
    data = request.get_json()
    try:
        name = data.name
        password = data.password
    except:
        return {
            'success': False,
            'err': 0
        }

    if not mr.rds.sismember(mr.USERNAMES, name):
        return {
            'success': False,
            'err': 1
        }

    stored_password = mr.rds.hget(mr.USER2PASS, name)
    if not check_password_hash(stored_password, password):
        return {
            'success': False,
            'err': 2
        }

    m_key = mr.rds.hget(mr.USER2MKEY, name)
    key2_encrypt = mr.rds.hget(mr.USER2KEY2E, name)
    return {
        'success': True,
        'm_key': m_key,
        'key2_encrypt': key2_encrypt
    }



if __name__ == "__main__":
    mr.initialize()
	# if not first time then remove this
    app.run(debug=True, port=5022)
