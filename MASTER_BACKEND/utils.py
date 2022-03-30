import secrets
import string


def generate_mkey():
  # generating random string of length 512
  key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(512))
  return key
