# solution to http://cryptopals.com/sets/3/challenges/20
# break a group of AES CTR ciphertexts statistically

import random
import math
import struct
import repeatingXOR
import base64
import repeatingXOR
from Crypto.Cipher import AES

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

# assume block length is 16
blockLength = 16
# generate random key
randomKey = randomByteGen(blockLength)
	
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
	
# encrypts all b64-encoded plaintexts in a given file with successive AES CTR operations
# returns list of bytearrays	
def getCipherTexts(fileName):
	plainList = []
	with open(fileName, 'r') as myfile:
		for line in myfile:
			plainList.append(base64.b64decode(line.strip()))
	cipherList = []
	nonce = 0
	for text in plainList:
		cipherList.append(cryptAES_CTR(text, randomKey, nonce))
	return cipherList

if __name__ == "__main__":
	cipherList = getCipherTexts("Challenge20Data.txt")
	# get minimum size of all ciphertexts
	minSize = min(len(cipherText) for cipherText in cipherList)
	print("Key size: " + str(minSize))
	longCipher = bytearray()
	for text in cipherList:
		longCipher = longCipher + text[0:minSize]
	# break repeating key XOR with same method that was used in Challenge 6
	plainBytes, keyBytes = repeatingXOR.breakRepeatingXOR(longCipher, minSize)
	print("Best key: " + str(keyBytes))
	print("Plaintexts: ")
	for i in range(0, len(cipherList)):
		print(plainBytes[i*minSize:(i+1)*minSize].decode("ascii"))