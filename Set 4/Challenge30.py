# solution to http://cryptopals.com/sets/4/challenges/30
# break an md4 keyed mac using length extension

import MD4Utils
import random
import struct

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

randomKey = randomByteGen(random.randint(10, 14))

# swap endianness of int
def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

# given key and message bytearrays, uses md4 to generate a keyed MAC
# returns MAC (hex string)
def getMAC(key, message):
	return MD4Utils.md4(key + message)
	
# get padding of message according to md4 algorithm
# returns glue message (bytes)
def getPadding(message_byte_length):
	padding = bytearray()
	# append the bit '1' to the message
	padding += b'\x80'
	# append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
	# is congruent to 56 (mod 64)
	padding += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
	# append length of message (before pre-processing), in bits, as 64-bit little-endian integer
	message_bit_length = message_byte_length * 8
	padding += struct.pack(b'<Q', message_bit_length)
	return padding
	
# forge a new MAC given a known initial message using length extension
# returns forged MAC (hex string)
def forgeMAC(initialMessage, newMessage):
	initialMAC = getMAC(randomKey, initialMessage)
	print("Initial MAC: " + str(initialMAC))
	# break md4 hash into registers
	a = int(initialMAC[0:8],   16)
	b = int(initialMAC[8:16],  16)
	c = int(initialMAC[16:24], 16)
	d = int(initialMAC[24:32], 16)
	# swap endianness of each register
	a = swap32(a)
	b = swap32(b)
	c = swap32(c)
	d = swap32(d)
	# calculate the amount of bytes we need to skip ahead
	msgLength = len(initialMessage) - len(initialMessage) % 64 + 64
	# forge the mac with the new parameters
	forgedMAC = MD4Utils.md4(newMessage, a, b, c, d, msgLength)
	return forgedMAC
	
if __name__ == "__main__":
	message = b"comment1=cooking MCs;userdata=foo;comment2=like a pound of bacon"
	print("Initial message: " + str(message))
	toAdd = b";admin=true"
	print("Adding the following: " + str(toAdd))
	
	print("Forged MAC:  " + forgeMAC(message, toAdd))
	print("Forged MAC should match with the real MAC:")
	padding = getPadding(len(message) + len(randomKey))
	print("Real MAC:    " + MD4Utils.md4(randomKey + message + padding + toAdd))