# solution to http://cryptopals.com/sets/4/challenges/28
# implementation of sha-1 keyed MAC

import SHA1Utils
import random

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

# given key and message bytearrays, uses sha-1 to generate a keyed MAC
# returns string
def getMAC(key, message):
	return SHA1Utils.sha1(key + message)

if __name__ == "__main__":
	key = randomByteGen(random.randint(10, 20))
	message = b"abc, 123"
	print(getMAC(key, message))