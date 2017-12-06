# solution to http://cryptopals.com/sets/2/challenges/16
# CBC bitflipping attack

import Challenge10
import Challenge15
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
# generate unknown random key and IV as a global
randomKey = randomByteGen(blockLength)
randomIV = randomByteGen(blockLength)

# given an input string, generates an encoded, ciphered string of data
# returns encoded ciphertext (bytes)
def getEncodedProfile(inputString):
	# clean encoding metacharacters ';' and '=' from input string
	cleanedInput = inputString.replace(";", "").replace("=", "")
	encodedPlainString = "comment1=cooking MCs;userdata=" + cleanedInput + ";comment2= like a pound of bacon" 
	# encrypt encoded plaintext string to encoded ciphertext bytes
	encodedPlainBytes = Challenge15.padBytes(bytearray(encodedPlainString, "ascii"), blockLength)
	encodedCipherBytes = Challenge10.encryptAES_CBC(bytes(encodedPlainBytes), randomKey, bytes(randomIV))
	return encodedCipherBytes

# decrypts provided bytes with CBC
# returns encoded plaintext (bytes)
def decryptProfile(cipherBytes):
	return Challenge10.decryptAES_CBC(bytes(cipherBytes), randomKey, bytes(randomIV))
	
# given ciphered encoded bytes, decrypt them and check for string ";admin=true;"
# returns boolean
def checkAdmin(cipherBytes):
	plainBytes = decryptProfile(cipherBytes)
	print("Decrypted bytes: \n" + str(plainBytes))
	if bytearray(";admin=true;", "ascii") in plainBytes:
		print("Admin entry found!")
		return True
	else:
		print("Admin entry not found.")
		return False

	
#      above this line: setting up the problem
#-----------------------------------------------------
#       below this line: solving the problem


# calculates the block of ciphertext needed to generate chosen plaintext
# takes the desired plaintext bytes (bytearray), the block number the plaintext will go in (int), and entirety of the ciphertext (bytearray), 
# this means that the block of ciphertext returned by this function will go in position (blockNo - 1)
# returns ciphertext block (bytearray)
def getNewBlock(desiredPlainBytes, blockNo, cipherBytes):
	# we cannot inject more than a block of plaintext at once
	if len(desiredPlainBytes) > blockLength:
		raise ValueError("Cannot fit " + int(len(desiredPlainBytes)) + " plaintext bytes into a block size of " + int(blockLength))

	# get padded plaintext bytes when user input is "" (assume this is known)
	plainBytes = bytearray("comment1=cooking MCs;userdata=;comment2= like a pound of bacon", "ascii")
	plainBytes = Challenge15.padBytes(plainBytes, blockLength)
	# get the block of plaintext that we want to overwrite with our chosen plaintext
	plainBlock = plainBytes[blockNo*blockLength:(blockNo+1)*blockLength]
	# get the block of ciphertext that we are going to modify to produce the modified plaintext
	cipherBlock = cipherBytes[(blockNo-1)*blockLength:blockNo*blockLength]
	
	for i in range(0, len(desiredPlainBytes)):
		# generate mask by xoring current plaintext byte and desired plaintext byte.
		# this mask holds the bits we need to flip in the ciphertext ('1' means we need to flip)
		mask = desiredPlainBytes[i] ^ plainBlock[i]
		# now, XOR'ing the mask with the current ciphertext byte yields the modified ciphertext byte
		cipherBlock[i] ^= mask
	return cipherBlock
		

if __name__ == "__main__":
	inputString = ""
	print("Creating profile with input string \"" + inputString + "\"...")
	encodedCipherBytes = getEncodedProfile(inputString)
	print("Initial ciphertext bytes: \n" + str(encodedCipherBytes))
	
	desiredBytes = bytearray(";admin=true;", "ascii")
	blockPos = 2
	newBlock = getNewBlock(desiredBytes, blockPos, encodedCipherBytes)
	# modified block goes in position (blockPos - 1)
	moddedCipherBytes = encodedCipherBytes[0:(blockPos-1)*blockLength] + newBlock + encodedCipherBytes[blockPos*blockLength:]
	print("Modified ciphertext bytes: \n" + str(moddedCipherBytes))
	
	checkAdmin(moddedCipherBytes)