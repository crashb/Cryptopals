# solution to http://cryptopals.com/sets/2/challenges/12
# decrypts an unknown string appended to a chosen plaintext, encrypted in AES ECB mode

import base64
import Challenge09
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
	with open('Challenge12Data.txt', 'r') as myfile:
		plainBytes += base64.b64decode(''.join(myfile.read().strip().split('\n')))
	plainBytes = Challenge09.padBytes(plainBytes, len(randomKey))
	cipherBytes = encryptAES_ECB(bytes(plainBytes), bytes(randomKey))
	return cipherBytes

	
#      above this line: setting up the problem
#-----------------------------------------------------
#       below this line: solving the problem

# 1. find the block length of the encryption process
# returns block length (int)
def findProcessBlockLength():
	# get an initial ciphertext value for when no bytes are provided
	testBytes = bytearray()
	initialCiphered = encryptionProcess(testBytes)
	# try block lengths from 3 - 32 (avoid 1 and 2 because they can return false positives easily)
	testBytes.append(0)
	testBytes.append(0)
	for i in range(3, 33):
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
# returns either "ECB" or "Not found"
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

# 3. call encryption process with a chosen plaintext whose purpose is to move the next unknown byte to the end of a controlled block
# called with block length (int), the block number we are looking at (int), and the byte we are looking at within that block (int)
# returns the first block (bytearray)
def getShortenedInputBlock(blockLength, blockNo, byteNo):
	# chosen string will be one byte short of the block length, minus the length of known plaintext in this block (byteNo)
	# consists of all 'a'
	chosenBytes = bytearray()
	for i in range(0, blockLength - byteNo - 1):
		chosenBytes.append(ord('a'))
	cipherBytes = encryptionProcess(chosenBytes)
	# return whichever block of ciphertext we are looking at
	return cipherBytes[blockNo*blockLength:(blockNo+1)*blockLength]
	
# 4. make dictionary of every possible last byte
# called with block length (int), any known plaintext from this block (bytearray), and the previous block's plaintext (bytearray)
# returns dictionary of ciphertext block and plaintext byte (bytearray, int)
def getPossibilities(blockLength, knownPlaintext, lastBlockPlaintext):
	# the chosen string will be precisely one block length long
	chosenBytePrefix = bytearray()
	# if in the first block (the last block's plaintext is an empty bytearray):
	# start with all 'a', then add any known plaintext to a length of (blockLength - 1)
	if lastBlockPlaintext == bytearray():
		for i in range(0, blockLength - len(knownPlaintext) - 1):
			chosenBytePrefix.append(ord('a'))
		for i in range(0, len(knownPlaintext)):
			chosenBytePrefix.append(knownPlaintext[i])
	# if in any other block:
	# add the previous (blockLength - 1) bytes of known plaintext, some of which are
	# from the last block and some of which are from this block
	else:
		for i in range(len(knownPlaintext) + 1, blockLength):
			chosenBytePrefix.append(lastBlockPlaintext[i])
		for i in range(0, len(knownPlaintext)):
			chosenBytePrefix.append(knownPlaintext[i])
			
	# by this point, chosenBytePrefix is only missing one byte at the end of it: the variable byte value.
	# iterate through all possible byte values to end our chosen string with, and populate dictionary with results
	possibilities = {}
	for i in range(0, 256):
		chosenBytes = bytearray(chosenBytePrefix)
		chosenBytes.append(i)
		cipherBytes = encryptionProcess(chosenBytes)
		possibilities[cipherBytes[0:blockLength]] = i
	return possibilities

# get a single block of plaintext
# takes block length (int), the number of the block to be obtained (int), and the last plaintext block (bytearray)
# returns the block of plaintext (bytearray)
def getPlaintextBlock(blockLength, blockNo, lastPlainBlock):
	plainBlock = bytearray()
	for i in range(0, blockLength):
		shortenedInputBlock = getShortenedInputBlock(blockLength, blockNo, len(plainBlock))
		# print("Result from shortened block: " + str(shortenedInputBlock) + "(Length: " + str(len(shortenedInputBlock)) + ")")
		bytePossi = getPossibilities(blockLength, plainBlock, lastPlainBlock)
		try:
			plainByte = bytePossi[shortenedInputBlock]
			plainBlock.append(plainByte)
		# if we hit a key error, either something went wrong, or we have hit the padding at the end of the message
		except KeyError:
			break
	# print("Plaintext block: " + str(plainBlock))
	return plainBlock

# find the plaintext message hidden in the encryptionProcess function, given the block length (int)
# returns the plaintext message (bytearray)
def getPlaintextMessage(blockLength):
	messageLength = len(encryptionProcess(bytearray()))
	message = bytearray()
	lastPlainBlock = bytearray()
	numBlocks = int(messageLength / blockLength)
	for i in range(0, numBlocks):
		plainBlock = getPlaintextBlock(blockLength, i, lastPlainBlock)
		message += plainBlock
		lastPlainBlock = plainBlock
	return message

if __name__ == "__main__":
	blockLength = findProcessBlockLength()
	print("Block length of encryption process: " + str(blockLength))
	encMode = detectProcessMode(blockLength)
	print("Mode of encryption process: " + encMode)
	print("Decrypting message...")
	messageBytes = getPlaintextMessage(blockLength)
	print(messageBytes.decode("ascii"))
	