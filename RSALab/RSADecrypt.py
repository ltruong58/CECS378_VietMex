import os
import os.path
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding as textPadder
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

def myDecryptHMAC(cipher_text, iv, EncKey, HMACKey, tag):
    hTag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())  # Creates a tag using our HMACKey generated
    hTag.update(cipher_text)  # Hash and authenticate our cipher text with our previous HMACKey and hTag

    # Verify method that will check against our cipher text  HMAC tag to see if they match
    # if not a InvalidSignature exception is thrown
    hTag.verify(tag)

    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv),
                    default_backend())  # Create the cipher that includes AES and CBC
    decryptor = cipher.decryptor()  # Create the decryptor Cipher Context interface
    # Decrypt the cipher text to plain text in the update method and finalize will return our final message as bytes
    plain_text = decryptor.update(cipher_text) + decryptor.finalize()

    unpadder = textPadder.PKCS7(128).unpadder()  # Creating the unpadder instance
    message = unpadder.update(plain_text)  # Update method will unpadd our plain text message and remove the padding
    message += unpadder.finalize()  # Finalize method will finish unpadding our plain text data and return it as bytes

    return message

def myFileDecryptHMAC(filepath, iv, tag, EncKey, HMACKey):
    file = open(filepath, 'rb')  # Open the file
    cipher_text = file.read()  # Extract whatever is in file
    file.close()  # close the file

    (message) = myDecryptHMAC(cipher_text, iv, EncKey, HMACKey,
                              tag)  # Call myDecryptHMAC method to decrypt the message from the file

    file = open(filepath, 'wb')  # Opens the file a
    file.write(message)  # write back the encoded cipher text
    file.close()  # Close the file

    return message

def myRSADecrypt(RSACipher, cipher_text, iv, tag, file_ext, RSA_privatekey_filepath):
    with open(RSA_privatekey_filepath, "rb") as key_file:  # Open our private key PEM file so that we may decrypt
        private_key = serialization.load_pem_private_key(
            # Load our serialized private key that is stored in the PEM file
            key_file.read(),  # Read our private key
            password=None,  # Since our private key was encrypted at serialization we have no password
            backend=default_backend()
        )

    concatenated_Keys_decrypted = private_key.decrypt(  # Decrypt our concatenated keys
        RSACipher,  # RSACipher needs to be decrypted so that we can get the EncKey and HMACKey
        padding.OAEP(  # Unpad our padder which provided the probabilistic encryption
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            # Unpad the mask generation function along with the SHA256 hash function
            algorithm=hashes.SHA256(),  # Decrypt our OAEP RSACipher with the hash function SHA25
            label=None
        )
    )

    EncKey = concatenated_Keys_decrypted[:32]  # We get up to 32 bits of our concatenatedKey because the Encryption key is 32 bits
    HMACKey = concatenated_Keys_decrypted[32:64]  # The HMAC key is also 32 bits so we get the other 32 bits for this key

    # After getting the Encryption Key and HMAC Key we can now decrypt the message in our file path and return the message(or data) inside
    message = myFileDecryptHMAC(filepath, iv, tag, EncKey, HMACKey)

    return message

# ------------------MAIN------------------------------
# GLOBAL VARIABLES
filepath = 'testFile3.txt'
RSA_publickey_filepath = 'publicKey.pem'
RSA_privatekey_filepath = 'privateKey.pem'
block_size = 16
ENC_KEY_SIZE = 32 #Our key encryption key size
KEY_EXPONENT = 65537 #Exponent variable used for our private and public key generation
KEY_SIZE = 2048 #The size of our public and private key sizes

#We call the RSAKeyGen method to generate a public and private key
#It will first check if we have public and private PEM files in our directory
#If they already exist it will return and perform myRSAEncrypt
RSAKeyGen(RSA_publickey_filepath, RSA_privatekey_filepath)

# RSA Encryption
(RSACipher, cipher_text, iv, tag, file_ext) = myRSAEncrypt(filepath, RSA_publickey_filepath)

# RSA Decryption
(message) = myRSADecrypt(RSACipher, cipher_text, iv, tag, file_ext, RSA_privatekey_filepath)

print("Encryption Results")
print(RSACipher)
print(cipher_text)
print(iv)
print(tag)
print(file_ext)
print("Decryption Results")
print(message)