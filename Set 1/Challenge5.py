# solution to http://cryptopals.com/sets/1/challenges/5
# implementation of repeating-key XOR

import binascii

# singleByteXOR performs the single-byte XOR operation on a byte array xorBytes with a supplied key
# returns a byte array
def singleByteXOR(xorBytes, key):
	xorResult = bytearray()
	for byte in xorBytes:
		xorResult.append(byte ^ key)
	return xorResult

# repeatingKeyXOR takes two byteArrays as arguments: the bytes to be XOR'd, and the bytes used as a key.
# returns a byte array
def repeatingKeyXOR(initialBytes, keyBytes):
	keyIndex = 0
	finalBytes = bytearray()
	for byte in initialBytes:
		finalBytes.append(byte ^ keyBytes[keyIndex])
		if keyIndex < len(keyBytes) - 1:
			keyIndex += 1
		else:
			keyIndex = 0
	return finalBytes
	
if __name__ == "__main__":
	plainText = "Burning 'em, if you ain't quick and nimble" + "\n" + "I go crazy when I hear a cymbal"
	key = "ICE"
	plainBytes = bytearray(plainText, "ascii")
	keyBytes = bytearray(key, "ascii")
	cipherBytes = repeatingKeyXOR(plainBytes, keyBytes)
	cipherHex = binascii.hexlify(cipherBytes)
	print(cipherHex.decode("ascii"))