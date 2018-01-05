# solution to http://cryptopals.com/sets/4/challenges/27
# recover the key from CBC with IV=key

import AESUtils
import random

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

# set blocklength to 16 - assume it is known
blockLength = 16
# generate unknown random key
randomKey = randomByteGen(blockLength)

# encrypts a bytearray in CBC mode with IV = key
# returns encrypted bytearray
def encryptBytes(plainBytes):
	return AESUtils.encryptAES_CBC(plainBytes, randomKey, randomKey)
	
# decrypts a bytearray in CBC mode with IV = key
# returns decrypted bytearray
def decryptBytes(cipherBytes):
	return AESUtils.decryptAES_CBC(cipherBytes, randomKey, randomKey)

# checks if there are any high-ascii values in a plaintext
# if plaintext is compliant: returns null
# if plaintext is non-compliant: returns plaintext bytes
def verifyCompliance(plainBytes):
	for byte in plainBytes:
		if byte > 127:
			print("Error: noncompliant plaintext bytes! \n" + str(plainBytes))
			return plainBytes
	return
	
if __name__ == "__main__":
	# create plaintext with 3 blocks: first block all "a", second "b", third "c"
	plainBytes = bytearray("a", "ascii") * blockLength + bytearray("b", "ascii") * blockLength + bytearray("c", "ascii") * blockLength
	cipherBytes = encryptBytes(plainBytes)
	# replace 2nd block with 0
	for i in range(0, blockLength):
		cipherBytes[blockLength + i] = 0
	# replace 3rd block with 1st block
	for i in range(0, blockLength):
		cipherBytes[2*blockLength + i] = cipherBytes[i]
	modPlainBytes = decryptBytes(cipherBytes)
	verifyCompliance(modPlainBytes)
	# now P'_1 XOR P'_3 yields the IV, which equals the key
	key = bytearray()
	for i in range(0, blockLength):
		key.append(modPlainBytes[i] ^ modPlainBytes[2*blockLength + i])
	print("Calculated key: " + str(key))
	print("Actual key:     " + str(randomKey))