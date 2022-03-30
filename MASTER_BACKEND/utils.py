<<<<<<< HEAD
def get_node_url(node_ip):
  return f'http://{node_ip}:8000'
=======
import secrets
import string


def generate_mkey():
  # generating random string of length 512
  key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(512))
  return key
>>>>>>> vishal
