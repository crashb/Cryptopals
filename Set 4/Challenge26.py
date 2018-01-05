# solution to http://cryptopals.com/sets/4/challenges/26
# CTR bitflipping attack

import AESUtils
import random
import struct

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

# set blocklength to 16 - assume it is known
blockLength = 16
# generate unknown random key and nonce
randomKey = randomByteGen(16)
nonceBytes = randomByteGen(8)
randomNonce = struct.unpack('<Q', nonceBytes)[0]

# given an input string, generates an encoded, ciphered string of data
# returns encoded ciphertext (bytes)
def getEncodedProfile(inputString):
	# clean encoding metacharacters ';' and '=' from input string
	cleanedInput = inputString.replace(";", "").replace("=", "")
	encodedPlainString = "comment1=cooking MCs;userdata=" + cleanedInput + ";comment2= like a pound of bacon"
	encodedPlainBytes = bytearray(encodedPlainString, "ascii")
	# encrypt encoded plaintext string to encoded ciphertext bytes
	encodedCipherBytes = AESUtils.cryptAES_CTR(encodedPlainBytes, randomKey, randomNonce)
	return encodedCipherBytes

# decrypts provided bytes with CTR
# returns encoded plaintext (bytes)
def decryptProfile(cipherBytes):
	return AESUtils.cryptAES_CTR(cipherBytes, randomKey, randomNonce)
	
# given ciphered encoded bytes, decrypt them and check for string ";admin=true;"
# returns boolean
def checkAdmin(cipherBytes):
	plainBytes = decryptProfile(cipherBytes)
	if bytearray(";admin=true;", "ascii") in plainBytes:
		print("Admin entry found!")
		return True
	else:
		print("Admin entry not found.")
		return False
		
#      above this line: setting up the problem
#-----------------------------------------------------
#       below this line: solving the problem

# modifies ciphertext to generate chosen plaintext
# takes the desired plaintext bytes (bytearray), the byte offset for the new bytes (int), and entirety of the ciphertext (bytearray)
# returns ciphertext block (bytearray)
def modifyCipherBytes(desiredPlainBytes, offset, cipherBytes):
	# plaintext bytes when user input is "" (assume this is known)
	plainBytes = bytearray("comment1=cooking MCs;userdata=;comment2= like a pound of bacon", "ascii")
	newCipherBytes = bytearray(cipherBytes)
	for i in range(0, len(desiredPlainBytes)):
		# generate mask by XOR'ing desired plaintext byte and current plaintext byte (known)
		mask = desiredPlainBytes[i] ^ plainBytes[i + offset]
		# XOR'ing the mask with the current ciphertext byte yields the modified ciphertext byte
		newCipherBytes[i + offset] ^= mask
	return newCipherBytes

if __name__ == "__main__":
	inputString = ""
	print("Creating profile with input string \"" + inputString + "\"...")
	encodedCipherBytes = getEncodedProfile(inputString)
	print("Initial ciphertext bytes: \n" + str(encodedCipherBytes))
	
	desiredBytes = bytearray(";admin=true;", "ascii")
	editedCipher = modifyCipherBytes(desiredBytes, 9, encodedCipherBytes)
	print("Modified ciphertext bytes: \n" + str(editedCipher))
	checkAdmin(editedCipher)