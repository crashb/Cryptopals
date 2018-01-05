# solution to http://cryptopals.com/sets/4/challenges/25
# break "random access read/write" AES CTR

import base64
import math
import struct
import random
import AESUtils

blockLength = 16

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes
	
# XORs two bytearrays
# returns a bytearray that is the result of the operation, length same length as first argument supplied
def streamXOR(dest, source):
	resultBytes = bytearray(dest)
	for i in range(0, len(dest)):
		resultBytes[i] ^= source[i]
	return resultBytes
	
# get random key (bytearray)
randomKey = randomByteGen(16)
# get random 64-bit nonce (int)
nonceBytes = randomByteGen(8)
randomNonce = struct.unpack('<Q', nonceBytes)[0]

# encryption process
# returns encrypted bytearray
def encryptionProcess():
	inputB64 = ''
	with open("Challenge25Data.txt", 'r') as myfile:
		inputB64 = ''.join(myfile.read().strip().split('\n'))
	inputBytes = base64.b64decode(inputB64)
	outputBytes = AESUtils.cryptAES_CTR(inputBytes, randomKey, randomNonce)
	return outputBytes

# edits encrypted ciphertext
# returns encrypted bytearray
def edit(cipherBytes, offset, newBytes):
	editedBytes = bytearray(cipherBytes)
	numBlocks = math.ceil(len(newBytes) / blockLength) + 1 # max number of blocks newBytes can be in
	startBlock = int(offset / blockLength)
	startByte = offset % blockLength # position of first byte in first block
	keyStream = AESUtils.getCTRKeystream(numBlocks, startBlock, randomKey, randomNonce)
	
	# decrypt relevant bytes to get a ciphertext bytearray, but bytes we are editing are plaintext
	for i in range(0, len(newBytes)):
		editedBytes[offset + i] ^= keyStream[startByte + i]
	# replace plaintext bytes with new bytes
	editedBytes[offset:offset + len(newBytes)] = newBytes
	# encrypt new bytes with relevant bytes of keystream
	for i in range(0, len(newBytes)):
		editedBytes[offset + i] ^= keyStream[startByte + i]
	return editedBytes

if __name__ == "__main__":
	encryptedBytes = encryptionProcess()
	# replacing the whole plaintext with 0 will cause the edited ciphertext to be equal to the keystream!
	newBytes = b'\x00' * len(encryptedBytes)
	keyStreamBytes = edit(encryptedBytes, 0, newBytes)
	# then simply XOR the keystream with the original ciphertext to recover the plaintext
	plainBytes = streamXOR(encryptedBytes, keyStreamBytes)
	print("Plain bytes: " + str(plainBytes))