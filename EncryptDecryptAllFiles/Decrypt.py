import os
import os.path
import json
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding as textPadder
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


def myFileDecryptHMAC(cipher_text, iv, tag, EncKey, HMACKey, filepath):

    hmacTag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())  # Creates a tag using our HMACKey generated
    hmacTag.update(cipher_text)  # Hash and authenticate our cipher text with our previous HMACKey and hTag

    # Verify method that will check against our cipher text  HMAC tag to see if they match
    # if not a InvalidSignature exception is thrown
    hmacTag.verify(tag)

    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv),default_backend())  # Create the cipher that includes AES and CBC
    decryptor = cipher.decryptor()  # Create the decryptor Cipher Context interface
    # Decrypt the cipher text to plain text in the update method and finalize will return our final message as bytes
    plain_text = decryptor.update(cipher_text) + decryptor.finalize()

    unpadder = textPadder.PKCS7(128).unpadder()  # Creating the unpadder instance
    message = unpadder.update(plain_text)  # Update method will unpadd our plain text message and remove the padding
    message += unpadder.finalize()  # Finalize method will finish unpadding our plain text data and return it as bytes

    return message


def myRSADecrypt(filepath, RSACipher, cipher_text, iv, tag, file_ext, RSA_privatekey_filepath):

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
    message = myFileDecryptHMAC(cipher_text, iv, tag, EncKey, HMACKey, filepath)

    return message

def getPrivateKeyPath(testDir):

    for files in os.listdir(testDir): #Get a list of files in the directory
        if files == "privateKey.pem": #If there is a private key file in the directory

            privateKeyPath = testDir+'/privateKey.pem' #Set the private key filepath

            return privateKeyPath #return the private key filepath

def decryptEverything(testDir, privateKeyPath):

    for root, dirs, filesToDecrypt in os.walk(testDir): #Traverse through the directory
        for files in filesToDecrypt: #Traverse through the files in the directory
            if files.endswith('.json'): #If the files end with the json file extension that means they hold encrypted data

                file_Path = root + "/" + files #Set the filepath as the file and the root directory address
                jsonFile = open(file_Path, "r")  #Open each json file
                jsonData = jsonFile.read() #Read the content in each json file

                JSONObject = json.loads(jsonData) #Load the json file data to our JSON object

                # Puts each value of each key in a variable to be used later
                #Decode our data so that we may pass into our myRSADecrypt method that is called
                stbCiphertext = JSONObject["Ciphertext"].encode('ascii')
                decodedCiphertext = base64.decodebytes(stbCiphertext)
                stbEncryptedKeys = JSONObject["RSACipher"].encode('ascii')
                decodedEncryptedKeys = base64.decodebytes(stbEncryptedKeys)
                stbHMACTag = JSONObject["Tag"].encode('ascii')
                decodedHMACTag = base64.decodebytes(stbHMACTag)
                stbIV = JSONObject["IV"].encode('ascii')
                decodedIV = base64.decodebytes(stbIV)
                ext = JSONObject["File Extension"]

                #Call the RSA Decrypt method and pass in our decoded values to decrypt
                message = myRSADecrypt(file_Path, decodedEncryptedKeys, decodedCiphertext, decodedIV, decodedHMACTag, ext, privateKeyPath)
                filename = os.path.splitext(file_Path)[0]
                #Create the decrypted file dir filepath
                originalFilePath = filename + ext

                #Open the new filepath for the decrypted file
                file = open(originalFilePath, "wb")
                file.write(message) #Write our decrypted ciphertext message into the new file
                file.close()
                jsonFile.close()
                os.remove(file_Path)
				

'''
----------------------------MAIN METHOD-------------------------------------------------
'''

BLOCK_SIZE = 16 #used for the IV
ENC_KEY_SIZE = 32 #Our key encryption key size
KEY_EXPONENT = 65537 #Exponent variable used for our private and public key generation
KEY_SIZE = 2048 #The size of our public and private key sizes

testDir = os.getcwd()


privateKeyPath = getPrivateKeyPath(testDir) #Get the private key filepath for decrypting

decryptEverything(testDir, privateKeyPath) #DECRYPT every file in the directory

deleteOldJSONFiles(testDir) #Delete the json files after decrypting
