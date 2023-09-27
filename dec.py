import argparse
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

# Create an argument parser
parser = argparse.ArgumentParser(description='Process data argument')
parser.add_argument('-d', '--data', help='Input data')

# Parse the arguments
args = parser.parse_args()

def aes_cbc_decrypt(ciphertext, key, iv):
    # Convert the key and IV to bytes
    key = key.encode('utf-8')
    iv = iv.encode('utf-8')

    # Create a Cipher object with AES CBC algorithm and PKCS7 padding
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext and remove the padding
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()

    # Return the decrypted plaintext as a string
    return unpadded_plaintext.decode('utf-8')

ciphertext = b64decode(args.data)
key = "*********0052021"
iv = "*********052021"

decrypted_data = aes_cbc_decrypt(ciphertext, key, iv)
print(decrypted_data)
