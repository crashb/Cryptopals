# solution to http://cryptopals.com/sets/3/challenges/24
# bruteforce mt19937 stream cipher and check password reset token

import time
import random
from Challenge21 import MT19937

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

# XORs two bytearrays
# returns a bytearray that is the result of the operation, same length as first argument supplied
def streamXOR(dest, source):
	resultBytes = bytearray(dest)
	for i in range(0, len(dest)):
		resultBytes[i] ^= source[i]
	return resultBytes
	
# creates an MT19937 object given an int seed to generate key bytes, which are xored against startBytes
# returns result of symmetrical cipher (bytearray)
def randomCipher(startBytes, seed):
	randomGen = MT19937(seed)
	keyBytes = bytearray()
	for i in range(len(startBytes)):
		# append least significant byte of number to key bytes
		newKeyByte = randomGen.extract_number() & 0xFF
		keyBytes.append(newKeyByte)
	resultBytes = streamXOR(startBytes, keyBytes)
	return resultBytes
	
# part 1:
# bruteforce a MT19937 cipher, given a known plaintext, by trying all 16-bit keys
# return key (int)
def bruteforceRandomCipher(cipherBytes, knownPlaintext):
	knownBytes = bytearray(knownPlaintext, "ascii")
	for i in range(2**16):
		testBytes = randomCipher(cipherBytes, i)
		if knownBytes in testBytes:
			return i
	raise ValueError("Key not found")

# generate a token using MT19937 seeded from current time
# returns token (int)
def generateToken():
	currentTime = int(time.time())
	randomGen = MT19937(currentTime)
	return randomGen.extract_number()
	
# check if a given value is the product of an MT19937 seeded from current time
# returns boolean
def checkToken(token):
	currentTime = int(time.time())
	for i in range(currentTime - 5, currentTime + 5):
		randomGen = MT19937(i)
		if randomGen.extract_number() == token:
			return True
	return False
	
if __name__ == "__main__":
	# given a known plaintext, append a random number of random bytes
	plainText = "AAAAAAAAAAAAAA"
	prefix = randomByteGen(random.randint(0, 15))
	plainBytes = prefix + bytearray(plainText, "ascii")
	# generate a random key and encrypt with MT19937 stream cipher
	keyVal = random.randint(0, 65535)
	cipherBytes = randomCipher(plainBytes, keyVal)
	# solve part 1
	print("Part 1: Bruteforcing MT19937 cipher...")
	bruteforcedKey = bruteforceRandomCipher(cipherBytes, plainText)
	print("Key found: " + str(bruteforcedKey))
	# solve part 2
	print("Part 2: Generating token seeded with current time...")
	token = generateToken()
	if checkToken(token):
		print("Token is a product of MT19937!")
	else:
		print("Token is *not* a product of MT19937 - something went wrong")