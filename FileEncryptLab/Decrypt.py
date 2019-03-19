import os
import os.path

from Encryptor import key, iv

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def myDecrypt(key, iv, cipher_text):

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()) #Create the cipher that includes AES and CBC
    decryptor = cipher.decryptor() #Create the decryptor
    plaintext = decryptor.update(cipher_text) + decryptor.finalize() #Decrypt the cipher text to plain text

    unpadder = padding.PKCS7(128).unpadder() #Creating the unpadder
    message = unpadder.update(plaintext) #unpad the padded plain text
    message += unpadder.finalize()

    return message

def myFileDecrypt(filepath, key, iv):

    file = open(filepath, 'rb') #Open the file
    cipher_text = file.read() #Read the cipher text in the file
    file.close()

    (message) = myDecrypt(key, iv, cipher_text) #Call the myDecrypt

    file = open(filepath, 'wb')
    file.write(message)
    file.close()

    return message

filepath = 'test2.txt'

(message) = myFileDecrypt(filepath, key, iv)

print(message)
