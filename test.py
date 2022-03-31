from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

# https://stackoverflow.com/questions/28426102/python-crypto-rsa-public-private-key-with-large-file
aes_key = get_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_EAX)
data = open('/Users/vishal/Downloads/iitd_things/8th_Sem/col726_numerical_algo/assignment_4/Distributed-instagram/USER_APP/user_data/uploads/2022-03-31_10.43.52.746460redis6justin-maller.jpg', 'rb').read()
ciphertext, tag = cipher.encrypt_and_digest(data)

# Now aes_key using encrypt key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(user.get_key2_encrypt().encode()))
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

encoded_info_dict = {'nonce': cipher.nonce, 'ciphertext': ciphertext, 'tag': tag,
                     'encrypted_aes_key': encrypted_aes_key}
encoded_info = pickle.dumps(encoded_info_dict)
