import os
import os.path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding
from EncryptorMAC import iv, tag, HMACKey, EncKey

block_size = 16
key_size = 32

def myDecryptHMAC(cipher_text, iv, EncKey, HMACKey, tag):

    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(cipher_text)
    h.verify(tag)

    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(cipher_text) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(message)
    message += unpadder.finalize()

    return message

def myFileDecryptHMAC(filepath, iv, tag):

    EncKey = os.urandom(key_size)  # Generate a key that is 32 bytes
    HMACKey = os.urandom(key_size)  # Generate an hmac key that is 32 bytes

    file = open(filepath, 'rb')  # Open the file
    cipher_text = file.read()  # Extract whatever is in file
    file.close()  # close the file

    (message) = myDecryptHMAC(cipher_text, iv, EncKey, HMACKey, tag)  # Call myEncrypt method to encrypt the message from the file

    file = open(filepath, 'wb')  # Opens the file a
    file.write(message)  # write back the encoded cipher text
    file.close()  # Close the file

    return message


filepath = 'test3.txt'

(message) = myFileDecryptHMAC(filepath)

print(message)
