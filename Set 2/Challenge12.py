# solution to http://cryptopals.com/sets/2/challenges/12
# decrypts an unknown string appended to a chosen plaintext

import base64
from Crypto.Cipher import AES

# generate unknown random key as a global
randomKey = randomByteGen(16)

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(randint(0, 255))
	return randomBytes

# decrypts AES cipher in ECB mode.  arguments are cipherBytes (bytes) and key (bytes)
# returns plaintext (bytes)
def decryptAES_ECB(cipherBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.decrypt(cipherBytes)
	
# encrypts AES cipher in ECB mode.  arguments are plainBytes (bytes) and key (bytes)
# returns ciphertext (bytes)
def encryptAES_ECB(plainBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.encrypt(plainBytes)
	
# this function is meant to represent the inner workings of the server - we normally
# wouldn't know precisely what's going on in here.
def encryption_oracle(plainBytes):
	# append unknown plaintext bytes to plaintext
	with open('Challenge10Data.txt', 'r') as myfile:
		plainBytes += base64.b64decode(''.join(myfile.read().strip().split('\n')))
	
	

if __name__ == "__main__":
	
	