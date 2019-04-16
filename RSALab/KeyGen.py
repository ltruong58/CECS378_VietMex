def KeysExist(RSA_publickey_filepath, RSA_privatekey_filepath):  # Method will check if public and private keys exist in the current directory

    # Will return True if it exists, False if it does not
    existsPublic = os.path.isfile(RSA_publickey_filepath) #Check to see if the public key PEM file exists in the directory
    existsPrivate = os.path.isfile(RSA_privatekey_filepath) #Check to see if the private key PEM file exists in the directory

    return existsPublic, existsPrivate

def RSAKeyGen(RSA_publickey_filepath, RSA_privatekey_filepath):  # Method will generate a serialized public and private key and then write them to a PEM file(one for each key)

    #Call the KeysExist method to check if the PEM filepaths exist for the public and private key
    existsPublic, existsPrivate = KeysExist(RSA_publickey_filepath, RSA_publickey_filepath)

    #If the public or private key PEM filepaths do not exist in the directory then we generate
    #a new private key PEM file and a new public key PEM file
    if(existsPublic == False or existsPrivate == False):
        # Generate a private key
        # Public exponet is the Fermat prime numbers used for randomization
        # Key size is the length of the modulus in bits
        # This will return an instance of an RSAPrivateKey
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        # Generate a public key from the values in our private key
        public_key = private_key.public_key()

        # Serializing the private key so that it can be encoded into bits and be transmitted
        # AKA Key Serialization
        # Both return serialized keys
        privKey = private_key.private_bytes(  # We use the RSAPrivateKeyWithSerialization interface to serialize our key
            encoding=serialization.Encoding.PEM,
            # Encoding type in this case is PEM which is base64 format with delimiter
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            # Private key format for our key which includes the header and footer
            encryption_algorithm=serialization.NoEncryption()
            # Encryption algorithm to be used for the serializtion, not used in our case
        )
        # Serializing the public key so that it can be encoded into bits and be transmitted
        pubKey = public_key.public_bytes( # We use the RSAPrivateKeyWithSerialization interface to serialize our public key
            encoding=serialization.Encoding.PEM, # Encoding type in this case is PEM which is base64 format with delimiter
            format=serialization.PublicFormat.SubjectPublicKeyInfo # Using the typical public key format for our public key
        )
        # Generate a publicKey.pem file that will store our serialized public key
        file = open('publicKey.pem', 'wb')  # Create publicKey.pem file
        file.write(pubKey)  # Write our serialized public key to the PEM file
        file.close()  # close the file after writing

        # Generate a privateKey.pem file that will store our serialized private key
        file = open('privateKey.pem', 'wb')  # Create the privateKey.pem file
        file.write(privKey)  # Write our serialized private key to the PEM file
        file.close()  # Close the file after writing

    #Else if the public key PEM file and the private key PEM filepath exist
    #in the directory then we return back to the main and start encrypting
    else:
        print("Keys exist")
        return #return if the keys exists