# solution to http://cryptopals.com/sets/2/challenges/14
# decrypts an unknown string of target-bytes, when the following format is followed:
# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

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

# set blocklength to 16 - assume it is known
blockLength = 16
# generate unknown random key and random prefix as a global
randomKey = randomByteGen(blockLength)
randomPrefix = randomByteGen(randint(0, 255))

# padBytes takes a bytearray of bytes to pad, as well as a block size to pad to
# returns a bytearray of padded bytes
def padBytes(bytesToPad, blockSize):
	numPadBytes = blockSize - (len(bytesToPad) % blockSize)
	paddedBytes = bytesToPad
	for i in range(0, numPadBytes):
		paddedBytes.append(4)
	return paddedBytes
	
# encrypts AES cipher in ECB mode.  arguments are plainBytes (bytes) and key (bytes)
# returns ciphertext (bytes)
def encryptAES_ECB(plainBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.encrypt(plainBytes)

# takes a bytearray of plainBytes, prepends a random number of random bytes to it,
# appends some unknown plaintext bytes to it, and encrypts under ECB mode using a random key.
# returns ciphered bytes (bytes)
# this function is meant to represent the inner workings of the server - we normally
# wouldn't know precisely what's going on in here.
def encryptionProcess(givenBytes):
	# begin with randomPrefix, and append provided givenBytes to it
	plainBytes = bytearray(randomPrefix)
	plainBytes += bytearray(givenBytes)
	# append unknown plaintext bytes to plaintext
	with open('Challenge14Data.txt', 'r') as myfile:
		plainBytes += base64.b64decode(''.join(myfile.read().strip().split('\n')))
	plainBytes = padBytes(plainBytes, len(randomKey))
	cipherBytes = encryptAES_ECB(bytes(plainBytes), bytes(randomKey))
	return cipherBytes

	
#      above this line: setting up the problem
#-----------------------------------------------------
#       below this line: solving the problem

# checks a bytearray for any consecutive matching blocks
# returns the block number of the first matching block (int)
# if no matches are found, returns -1
def findMatchingBlocks(bytesToCheck):
	numBlocks = int(len(bytesToCheck) / blockLength)
	for i in range(0, numBlocks - 1):
		if bytesToCheck[i*blockLength:(i+1)*blockLength] == bytesToCheck[(i+1)*blockLength:(i+2)*blockLength]:
			return i
	return -1

# get the number of needed to complete the first block of attacker-controlled text
# returns number of bytes needed and index of first matching block [(int), (int)]
def getPrepadBytes():
	# begin by setting the attacker-controlled text to 2 block lengths full of 'a'.
	# we are going to check if we have any matching blocks in the ciphertext; if we
	# don't, add another 'a' and try again.  by the time we reach 3 block lengths, we
	# should have found 2 matching blocks in the ciphertext.
	testPrepadBytes = bytearray()
	for i in range(0, 2*blockLength):
		testPrepadBytes.append(ord('a'))
	numBytes = 0
	for i in range(0, 16):
		testCipherBytes = encryptionProcess(testPrepadBytes)
		blockIndex = findMatchingBlocks(testCipherBytes)
		if blockIndex != -1:
			return [numBytes, blockIndex]
		else:
			testPrepadBytes.append(ord('a'))
			numBytes += 1
	# we should have found 2 consecutive matching blocks by now
	print("Error: prepad bytes greater than block length")
	return [-1, -1]

# call encryption process with a chosen plaintext whose purpose is to move the next unknown byte to the end of a controlled block
# called with number of prepad bytes (int), the block number we are looking at (int), and the byte we are looking at within that block (int)
# returns the first block (bytearray)
def getShortenedInputBlock(prepadBytes, blockNo, byteNo):
	# chosen string starts with prepadBytes of 'a', to bring us to the start of the next block
	chosenBytes = bytearray()
	for i in range(0, prepadBytes):
		chosenBytes.append(ord('a'))
	# chosen string will be one byte short of the block after that, minus the length of known plaintext in this block (byteNo)
	# consists of all 'a'
	for i in range(0, blockLength - byteNo - 1):
		chosenBytes.append(ord('a'))
	cipherBytes = encryptionProcess(chosenBytes)
	# return whichever block of ciphertext we are looking at
	return cipherBytes[blockNo*blockLength:(blockNo+1)*blockLength]
	
# make dictionary of every possible last byte
# called with number of prepad bytes (int), the source block number (int), any known plaintext from this block (bytearray), and the previous block's plaintext (bytearray)
# returns dictionary of ciphertext block and plaintext byte (bytearray, int)
def getPossibilities(prepadBytes, sourceBlockNo, knownPlaintext, lastBlockPlaintext):
	# the chosen string will be prepadBytes of 'a', plus precisely one block length
	chosenBytePrefix = bytearray()
	for i in range(0, prepadBytes):
		chosenBytePrefix.append(ord('a'))
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
		possibilities[cipherBytes[sourceBlockNo*blockLength:(sourceBlockNo+1)*blockLength]] = i
	return possibilities

# get a single block of plaintext
# takes number of prepad bytes (int), the number of the block to be obtained (int), the source block number (int), and the last plaintext block (bytearray)
# returns the block of plaintext (bytearray)
def getPlaintextBlock(prepadBytes, blockNo, sourceBlockNo, lastPlainBlock):
	plainBlock = bytearray()
	for i in range(0, blockLength):
		shortenedInputBlock = getShortenedInputBlock(prepadBytes, blockNo, len(plainBlock))
		# print("Result from shortened block: " + str(shortenedInputBlock) + "(Length: " + str(len(shortenedInputBlock)) + ")")
		bytePossi = getPossibilities(prepadBytes, sourceBlockNo, plainBlock, lastPlainBlock)
		plainByte = bytePossi[shortenedInputBlock]
		# print("Plaintext byte: " + str(plainByte) + " (ASCII: " + chr(plainByte) + ")")
		plainBlock.append(plainByte)
	return plainBlock

# find the plaintext message hidden in the encryptionProcess function, given the number of prepad bytes (int)
# returns the plaintext message (bytearray)
def getPlaintextMessage():
	# get the number of prepad bytes and the index of the first manipulatable block (our source for determining the output of a given plaintext block)
	numPrepadBytes, sourceBlockNo = getPrepadBytes()
	# print("Number of bytes needed to complete block: " + str(numPrepadBytes))
	# print("First fully manipulatable block: " + str(sourceBlockNo) + " (expected: " + str(int(len(randomPrefix) / blockLength) + 1) + ")")
	
	# calculate number of blocks in message that comes after attacker-controlled text,
	# by rounding out the prefix blocks and subtracting the source block
	testMessage = bytearray()
	for i in range(0, numPrepadBytes):
		testMessage.append(ord('a'))
	messageLength = len(encryptionProcess(testMessage))
	lastPlainBlock = bytearray()
	numBlocks = int(messageLength / blockLength) - sourceBlockNo
	
	# iterate through blocks and add each one to message
	message = bytearray()
	for i in range(0, numBlocks):
		plainBlock = getPlaintextBlock(numPrepadBytes, i + sourceBlockNo, sourceBlockNo, lastPlainBlock)
		message += plainBlock
		lastPlainBlock = plainBlock
	return message

if __name__ == "__main__":
	print("Decrypting message...")
	messageBytes = getPlaintextMessage()
	print(messageBytes.decode("ascii"))