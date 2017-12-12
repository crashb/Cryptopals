# solution to http://cryptopals.com/sets/3/challenges/17
# CBC bitflipping / padding oracle attack

import base64
import random
import AESUtils
import paddingUtils

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes
	
# set blocklength to 16 - assume it is known
blockLength = 16
# generate unknown random key and IV as a global
randomKey = randomByteGen(blockLength)
randomIV = randomByteGen(blockLength)

# given a filename holding 10 different lines of base64 encoded text 
# returns ciphertext bytes (bytearray)
def getCiphertext(fileName):
	plainList = []
	with open(fileName, 'r') as myfile:
		for line in myfile:
			plainList.append(line.strip())
	plainText = random.choice(plainList)
	plainBytes = base64.b64decode(plainText)
	plainBytes = paddingUtils.padBytes(plainBytes, blockLength)
	cipherBytes = AESUtils.encryptAES_CBC(plainBytes, randomKey, randomIV)
	return cipherBytes
	
# returns true or false depending on if a ciphertext's padding is valid
# returns boolean
def validPadding(cipherBytes):
	try:
		plainBytes = AESUtils.decryptAES_CBC(cipherBytes, randomKey, randomIV)
		plainBytes = paddingUtils.unpadBytes(plainBytes, blockLength)
		return True
	except ValueError as e:
		# print(str(e))
		return False


#      above this line: setting up the problem
#-----------------------------------------------------
#       below this line: solving the problem

# The fundamental insight behind this attack is that the byte 01h is valid padding, and occur 
# in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

# finds one byte of plaintext by exploiting the padding oracle.
# needs two blocks of ciphertext: lastCipherBlock (bytearray), which is modified to decode a byte in cipherBlock (bytearray)
# the function also requires the number of the byte we are looking at (counting from the end of the block, int 1-16) as
# well as any known bytes from the block that have already been decrypted
# returns a byte of plaintext (int)
def findPlainByte(lastCipherBlock, cipherBlock, byteNo, knownBytes):
	# we are going to supply two blocks of ciphertext to the oracle:
	# the first block is the tampered ciphertext, and the second block is what we want to decode
	origByte = lastCipherBlock[-byteNo]
	blockPrefix = lastCipherBlock[:-byteNo]
	# set up suffix
	blockSuffix = bytearray()
	for i in range(0, len(knownBytes)):
		blockSuffix.append(knownBytes[i] ^ byteNo ^ lastCipherBlock[-(len(knownBytes) - i)])
	# start creating different ciphertexts to send
	for i in range(0, 256):
		newBlock = bytearray(blockPrefix)
		newBlock.append(i)
		newBlock += blockSuffix
		# now that we have our tampered block, add the desired ciphertext to it
		newBlock += cipherBlock
		if (validPadding(newBlock)):
			# edge case for if we are finding the final byte of the final block: there are
			# two cases where it can have valid padding, and one of them is with the original
			# byte.  we want to get rid of that possibility, so we just skip it.
			if i == origByte and byteNo == 1:
				continue
			# XORing the original ciphertext byte (origByte) with the decryption result
			# will yield the plaintext character, so:
			# if the padding is valid, we know that the plaintext byte = the supplied byte 
			# XORed with the original ciphertext byte and the padding number (byteNo)
			plainByte = i ^ origByte ^ byteNo
			# print("Valid byte: " + str(plainByte) + " (" + chr(plainByte) + ")")
			return plainByte
	print("No valid bytes found!")
	return -1
	
# find a full block of plaintext by exploiting the padding oracle.
# needs two blocks of ciphertext: lastCipherBlock (bytearray), which is modified to decode cipherBlock (bytearray)
# returns a plaintext block (bytearray)
def findPlainBlock(lastCipherBlock, cipherBlock):
	plainBytes = bytearray()
	for i in range(0, blockLength):
		newByte = findPlainByte(lastCipherBlock, cipherBlock, i + 1, plainBytes)
		plainBytes.insert(0, newByte)
	# print("Decrypted block: " + str(plainBytes))
	return plainBytes

# decrypts a message that was encrypted with AES CBC encryption.
# takes the ciphertext bytes (bytearray)
# returns the plaintext bytes (bytearray)
def findPlainMsg(cipherBytes):
	print("Decrypting message...")
	numBlocks = int(len(cipherBytes) / blockLength)
	lastCipherBlock = bytearray(randomIV)
	plainBytes = bytearray()
	# print("Initialization vector: " + str(randomIV))
	for i in range(0, numBlocks):
		cipherBlock = cipherBytes[i*blockLength:(i+1)*blockLength]
		plainBytes += findPlainBlock(lastCipherBlock, cipherBlock)
		lastCipherBlock = cipherBlock
	return plainBytes
	
if __name__ == "__main__":
	cipherText = getCiphertext("Challenge17Data.txt")
	plainMessage = findPlainMsg(cipherText)
	plainMessage = paddingUtils.unpadBytes(plainMessage, blockLength)
	print("Decrypted message: " + plainMessage.decode("ascii"))