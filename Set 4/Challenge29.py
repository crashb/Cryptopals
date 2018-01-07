# solution to http://cryptopals.com/sets/4/challenges/29
# break a sha-1 keyed mac using length extension

import SHA1Utils
import random
import struct

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

randomKey = randomByteGen(10) #TODO

# given key and message bytearrays, uses sha-1 to generate a keyed MAC
# returns MAC (hex string)
def getMAC(key, message):
	return SHA1Utils.sha1(key + message)
	
# pad message according to sha-1 algorithm
# returns glue message (bytearray)
def getPadding(message_byte_length):
	padding = bytearray()
	# append the bit '1' to the message
	padding += b'\x80'
	# append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
	# is congruent to 56 (mod 64)
	padding += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
	# append length of message (before pre-processing), in bits, as 64-bit big-endian integer
	message_bit_length = message_byte_length * 8
	padding += struct.pack(b'>Q', message_bit_length)
	return padding
	
# forge a new MAC given a known initial message using length extension
# returns forged MAC (hex string)
def forgeMAC(initialMessage, newMessage):
	initialMAC = getMAC(randomKey, initialMessage)
	# break sha-1 hash into registers
	a = int(initialMAC[0:8],   16)
	b = int(initialMAC[8:16],  16)
	c = int(initialMAC[16:24], 16)
	d = int(initialMAC[24:32], 16)
	e = int(initialMAC[32:40], 16)
	padding = getPadding(len(initialMessage) + 10) #TODO
	# calculate the amount of bytes we need to skip ahead
	msgLength = len(initialMessage) - len(initialMessage) % 64 + 64
	# forge the mac with the new parameters
	forgedMAC = SHA1Utils.sha1(newMessage, a, b, c, d, e, msgLength)
	return forgedMAC

if __name__ == "__main__":
	message = b"comment1=cooking MCs;userdata=foo;comment2=like a pound of bacon"
	print("Initial message: " + str(message))
	padding = getPadding(len(message) + 10) #TODO
	# SHA1Utils.sha1(randomKey + message + padding) # debug
	toAdd = b";admin=true"
	print("Adding the following: " + str(toAdd))
	
	print("Forged MAC: " + forgeMAC(message, toAdd))
	print("Real MAC:   " + SHA1Utils.sha1(randomKey + message + padding + toAdd))