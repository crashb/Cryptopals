# web application for challenge 31:
# http://cryptopals.com/sets/4/challenges/31
# uses web.py

import web
import time
from SHA1Utils import sha1
import binascii

randomKey = b'YELLOW SUBMARINE'
blockSize = 64

# XORs two bytearrays
# returns a bytearray that is the result of the operation, length same length as first argument supplied
def streamXOR(dest, source):
	resultBytes = bytearray(dest)
	for i in range(0, len(dest)):
		resultBytes[i] ^= source[i]
	return resultBytes

# given a fileName (string) and keyBytes (bytearray), get an HMAC for the file
# returns HMAC (hex string)
def getHMAC(fileName, key):
	keyBytes = bytearray(key)
	# keys longer than blockSize are shortened by hashing them
	if(len(keyBytes) > blockSize):
		keyBytes = bytearray.fromhex(sha1(keyBytes))
	
	# pad key with 0 to make it blockSize bytes long
	if(len(keyBytes) < blockSize):
		for i in range(0, blockSize - len(keyBytes)):
			keyBytes.append(0)
	
	o_key_pad = streamXOR(keyBytes, b'\x5c' * blockSize) # outer padded key
	i_key_pad = streamXOR(keyBytes, b'\x36' * blockSize) # inner padded key
	
	fileBytes = bytearray(fileName, "ascii")
	innerHash = bytearray.fromhex(sha1(i_key_pad + fileBytes))
	return sha1(o_key_pad + innerHash)
	
	
def insecure_compare(provided, expected):
	providedBytes = bytearray.fromhex(provided)
	expectedBytes = bytearray.fromhex(expected)
	for providedByte, expectedByte in zip(providedBytes, expectedBytes):
		if (providedByte != expectedByte):
			return False
		time.sleep(0.05)
	return True

urls = (
  '/test', 'index',
)

class index:
	def GET(self):
		user_data = web.input(file="", signature="")
		hmac = getHMAC(user_data.file, randomKey)
		valid = insecure_compare(user_data.signature, hmac)
		if not valid:
			return( "Error: invalid signature! \n" +
					"Submitted string:    " + user_data.file + " \n" +
					"Submitted signature: " + user_data.signature + " \n" +
					"Actual signature:    " + hmac)
		else:
			return("String \"" + user_data.file + "\" accepted as input!")
		
if __name__ == "__main__":
	app = web.application(urls, globals())
	app.run()