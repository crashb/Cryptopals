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
	
# given ciphered encoded bytes, decrypt them and check for string ";admin=true;"
# returns boolean
def checkAdmin(cipherBytes):
	plainBytes = Challenge10.decryptAES_CBC(bytes(cipherBytes), randomKey, bytes(randomIV))
	if bytearray(";admin=true;", "ascii") in plainBytes:
		print("Admin entry found!")
		return True
	else:
		print("Admin entry not found.")
		return False

	
#      above this line: setting up the problem
#-----------------------------------------------------
#       below this line: solving the problem

if __name__ == "__main__":
	inputString = ";admin=true;"
	encodedCipherBytes = getEncodedProfile(inputString)
	print("Encoded ciphertext bytes: " + str(encodedCipherBytes))
	checkAdmin(encodedCipherBytes)