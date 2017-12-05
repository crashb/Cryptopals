# solution to http://cryptopals.com/sets/2/challenges/11
# detects between ECB and CBC encryption modes

import Challenge10
from random import randint

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns random key (bytearray)
def randomByteGen(length):
	key = bytearray()
	for i in range(0, length):
		key.append(randint(0, 255))
	return key

# padBytes takes a bytearray of bytes to pad, as well as a block size to pad to
# returns a bytearray of padded bytes
def padBytes(bytesToPad, blockSize):
	numPadBytes = blockSize - (len(bytesToPad) % blockSize)
	paddedBytes = bytesToPad
	for i in range(0, numPadBytes):
		paddedBytes.append(4)
	return paddedBytes
	
# pads inputBytes (bytearray) on both sides with 5-10 random bytes, then encrypts inputBytes with a randomly generated 16-byte key.  
# half of the time, encrypts in ECB mode; the other half of the time, encrypts in CBC mode.
# outputs the encrypted bytes (bytearray)
def encryption_oracle(inputBytes):
	# add 5-10 bytes to beginning and end of inputBytes
	inputBytes = randomByteGen(randint(5, 10)) + inputBytes
	inputBytes += randomByteGen(randint(5, 10))
	# pad inputBytes to have an even number of 16-byte blocks
	padBytes(inputBytes, 16)
	# generate random key
	randomKey = randomByteGen(16)
	# flip a coin to encrypt with ECB or CBC mode
	if (randint(1, 2) == 1):
		print("Encrypting with ECB...")
		encryptedBytes = Challenge10.encryptAES_ECB(bytes(inputBytes), bytes(randomKey))
	else:
		print("Encrypting with CBC...")
		randomIV = randomByteGen(16)
		encryptedBytes = Challenge10.encryptAES_CBC(inputBytes, randomKey, randomIV)
	return encryptedBytes
	
# detectAESMode takes a ciphered bytearray, and returns a string identifying the mode
# returns either "ECB" or "CBC"
def detectAESMode(cipherBytes):
	# see if there are two identical blocks of ciphertext - if so, we are in ECB mode
	blocks = []
	for i in range(0, len(cipherBytes), 16):
		if cipherBytes[i:i+16] in blocks:
			return "ECB"
		blocks.append(cipherBytes[i:i+16])
	# otherwise, if there are not two identical blocks of ciphertext, we are likely in CBC mode
	# (or we are in ECB mode, and there were not two identical blocks of plaintext)
	return "CBC"

if __name__ == "__main__":
	# plaintext string with a lot of repeating 16-byte blocks in the middle (since that's how ECB is detected)
	plainString = "pad pad pad pad abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop pad pad pad pad"
	plainBytes = bytearray(plainString, "ascii")
	encryptedBytes = encryption_oracle(plainBytes)
	print("Encrypted bytes: " + str(encryptedBytes))
	mode = detectAESMode(encryptedBytes)
	print("Detected mode: " + mode)
