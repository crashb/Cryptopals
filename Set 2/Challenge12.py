# solution to http://cryptopals.com/sets/2/challenges/12
# decrypts an unknown string appended to a chosen plaintext

import base64
from Crypto.Cipher import AES
from random import randint

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(randint(0, 255))
	return randomBytes
	
# generate unknown random key as a global
randomKey = randomByteGen(16)

# padBytes takes a bytearray of bytes to pad, as well as a block size to pad to
# returns a bytearray of padded bytes
def padBytes(bytesToPad, blockSize):
	numPadBytes = blockSize - (len(bytesToPad) % blockSize)
	paddedBytes = bytesToPad
	for i in range(0, numPadBytes):
		paddedBytes.append(4)
	return paddedBytes

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

# takes a bytearray of plainBytes, appends some unknown plaintext bytes to it, and encrypts
# under ECB mode using a random key.
# returns ciphered bytes (bytes)
# this function is meant to represent the inner workings of the server - we normally
# wouldn't know precisely what's going on in here.
def encryptionProcess(givenBytes):
	plainBytes = bytearray(givenBytes)
	# append unknown plaintext bytes to plaintext
	with open('Challenge10Data.txt', 'r') as myfile:
		pass
		plainBytes += base64.b64decode(''.join(myfile.read().strip().split('\n')))
	plainBytes = padBytes(plainBytes, len(randomKey))
	cipherBytes = encryptAES_ECB(bytes(plainBytes), bytes(randomKey))
	return cipherBytes

# 1. find the block length of the encryption process
# returns block length (int)
def findProcessBlockLength():
	testBytes = bytearray()
	initialCiphered = encryptionProcess(testBytes)
	# try block lengths from 1 - 32
	for i in range(1, 33):
		testBytes.append(0)
		tryCiphered = encryptionProcess(testBytes)
		# if the first block of the initial cipher equals the second block of the cipher we are trying,
		# this block length must be the correct one (and equal to the key size)
		if initialCiphered[0:i] == tryCiphered[i:i*2]:
			return i
	# if we have tried all block lengths
	print("Error: block length not found")
	return -1
	
# 2. find the AES mode of the encryption process given blockLength (int)
# returns either "ECB" or "CBC"
def detectProcessMode(blockLength):
	# chosen string is twice the size of the block length and all 'a'
	chosenBytes = bytearray()
	for i in range(0, 2*blockLength):
		chosenBytes.append(ord('a'))
	cipherBytes = encryptionProcess(chosenBytes)
	# find if there are any duplicate blocks in cipherBytes.  if we are in ECB mode,
	# the first two blocks should be identical, since we start with two blocks of all 'a'
	blocks = []
	for i in range(0, len(cipherBytes), blockLength):
		if cipherBytes[i:i+blockLength] in blocks:
			return "ECB"
		blocks.append(cipherBytes[i:i+blockLength])
	# otherwise, if there are not two identical blocks of ciphertext, we are not in ECB mode
	print("Error: not able to detect ECB mode")
	return "Not found"

# 3. calls encryption process with a chosen plaintext that is exactly one byte short.
# returns the first block (bytearray)
def getShortenedInputBlock(blockLength):
	# chosen string is one byte short of the block length and all 'a'
	chosenBytes = bytearray()
	for i in range(0, blockLength - 1):
		chosenBytes.append(ord('a'))
	cipherBytes = encryptionProcess(chosenBytes)
	# return last byte of block
	return cipherBytes[0:blockLength]
	
# 4. makes dictionary of every possible last byte
# returns dictionary of ciphertext blocks and plaintext byte (bytearray, int)
def getPossibilities(blockLength):
	possibilities = {}
	for i in range(0, 256):
		# chosen string one block length, all 'a' but ends with i (byte value)
		chosenBytes = bytearray()
		for j in range(0, blockLength - 1):
			chosenBytes.append(ord('a'))
		chosenBytes.append(i)
		cipherBytes = encryptionProcess(chosenBytes)
		# add entry to dictionary
		possibilities[cipherBytes[0:blockLength]] = i
		# print("Set " + str(cipherBytes[0:blockLength]) + " to " + str(i))
	return possibilities

if __name__ == "__main__":
	blockLength = findProcessBlockLength()
	print("Block length of encryption process: " + str(blockLength))
	encMode = detectProcessMode(blockLength)
	print("Mode of encryption process: " + encMode)
	shortenedInputBlock = getShortenedInputBlock(blockLength)
	print("Shortened input block (encrypted): " + str(shortenedInputBlock))
	allBytes = getPossibilities(blockLength)
	# print("Possibilities: " + str(allBytes))
	firstPlainByte = allBytes[shortenedInputBlock]
	print("First plaintext byte (decrypted): " + str(firstPlainByte) + " (ASCII: " + chr(firstPlainByte) + ")")
	