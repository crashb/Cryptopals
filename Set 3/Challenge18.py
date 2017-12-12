# solution to http://cryptopals.com/sets/3/challenges/18
# implementation of AES CTR mode

import math
import struct
import base64
from Crypto.Cipher import AES

# assume block length is 16
blockLength = 16
	
# encrypts AES cipher in ECB mode.  arguments are plainBytes (bytes) and key (bytes)
# returns ciphertext (bytes)
def encryptAES_ECB(plainBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.encrypt(plainBytes)

# XORs two bytearrays
# returns a bytearray that is the result of the operation, length same length as first argument supplied
def streamXOR(dest, source):
	resultBytes = bytearray(dest)
	for i in range(0, len(dest)):
		resultBytes[i] ^= source[i]
	return resultBytes

# encrypts/decrypts AES in CTR mode.  the operation is symmetrical for encryption and decryption.
# returns bytearray
def cryptAES_CTR(startBytes, keyBytes, nonce):
	numBlocks = math.ceil(len(startBytes) / blockLength)
	counter = 0
	keyStream = bytearray()
	endBytes = bytearray()
	nonceBytes = struct.pack('<Q', nonce)
	for i in range(0, numBlocks):
		# pack counter int into 64-bit little endian format
		counterBytes = struct.pack('<Q', counter)
		# prepend nonceBytes to counter to create bytes that are then encrypted
		counterBytes = bytearray(nonceBytes) + counterBytes
		keyStream += encryptAES_ECB(bytes(counterBytes), bytes(keyBytes))
		counter += 1
	# xor our fully generated keyStream against startBytes all in one go
	resultBytes = streamXOR(startBytes, keyStream)
	return resultBytes
	
if __name__ == "__main__":
	input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	inputBytes = base64.b64decode(input)
	keyBytes = bytearray("YELLOW SUBMARINE", "ascii")
	nonce = 0
	resultBytes = cryptAES_CTR(inputBytes, keyBytes, nonce)
	print("Decoded message: " + resultBytes.decode("ascii"))