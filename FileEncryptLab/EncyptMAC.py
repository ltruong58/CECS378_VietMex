from os import urandom, path, remove
from cryptography.hazmat.primitives import padding,hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json 
import sys
# sys.setdefaultencoding() does not exist, here!
reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF8')

BLOCK_SIZE = 16  # Bytes.
KEY_SIZE = 32

#	Myencrypt
def Myencrypt( msg, EncKey, HMACKey):
	if(len(EncKey) != KEY_SIZE):
		raise ValueError('EncKey must be 32 bytes')
	# Padding the msg
	backend = default_backend()		
	padder = padding.PKCS7(128).padder()
	msg = padder.update(msg) # Add missing bits to the end of the message msg
	msg += padder.finalize()
	
	iv = urandom(BLOCK_SIZE) #16 bytes
	
	# Encrypt
	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	ct = encryptor.update(msg) + encryptor.finalize()
	
	#HMAC
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
	h.update(ct)
	tag = h.finalize()
	
	return ct, iv, tag	

#	Myfilencrypt
def Myfilencrypt( filepath):
	EncKey = (urandom(KEY_SIZE)) # Generate 32-byte EncKey
	HMACKey = (urandom(KEY_SIZE)) # Generate 32-byte HMACKey
	# Open file to read
	fr = open(filepath,'r') 
	msg = fr.read()
	fr.close()	
	
	#delete original file
	#remove(filepath)
	
	# Get file extension	
	filename, file_ext = path.splitext(filepath)
	
	# Encrypt the message
	c , iv, tag = Myencrypt(msg, EncKey, HMACKey)
	
	#message = bytes('the message to hash here').encode('utf-8')
	
	#c = bytes(c).decode('utf-8', 'ignore').encode('utf-8')
	##tag = bytes(tag).decode('utf-8', 'ignore').encode('utf-8')
	#iv = bytes(iv).decode('utf-8', 'ignore').encode('utf-8')
	#EncKey = bytes(EncKey).decode('utf-8', 'ignore').encode('utf-8')
	#HMACKey = bytes(HMACKey).decode('utf-8', 'ignore').encode('utf-8')
	
	#Store data in JSON file
	data = {			
			'c' : c,
			'iv' : iv,
			'tag' : tag,
			'EncKey' : EncKey,
			'HMACKey' : HMACKey,
			'file_ext' : file_ext
			}
			
	# Open file to write
	with open(filename + '.json', 'w') as outfile:
		json.dump(data, outfile, ensure_ascii=False)
	#json.dump(data, outfile, ensure_ascii=False)
	return c, iv, tag, EncKey, HMACKey, file_ext 
		


# MAIN

#filepath = input('File path: ')
filepath = 'test.txt'
c, iv, tag, EncKey, HMACKey, file_ext  = Myfilencrypt(filepath)

