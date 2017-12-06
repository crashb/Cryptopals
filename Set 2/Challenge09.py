# solution to http://cryptopals.com/sets/2/challenges/9
# implementation of PKCS#7 padding

# padBytes takes a bytearray of bytes to pad, as well as a block size to pad to
# returns padded bytes (bytearray)
def padBytes(bytesToPad, blockSize):
	numPadBytes = blockSize - (len(bytesToPad) % blockSize)
	paddedBytes = bytesToPad
	for i in range(0, numPadBytes):
		paddedBytes.append(numPadBytes)
	return paddedBytes

# unpadBytes takes a bytearray of padded bytes and strips the padding off
# returns unpadded bytes (bytearray)
def unpadBytes(bytesToUnpad, blockSize):
	numToUnpad = bytesToUnpad[-1]
	unpadded = bytearray(bytesToUnpad)
	for i in range(0, numToUnpad):
		unpadded = unpadded[:-1]
	return unpadded
	
if __name__ == "__main__":
	someBytes = bytearray("yellow bubmarin", "ascii")
	paddedBytes = padBytes(someBytes, 16)
	print("Padded bytes: " + str(paddedBytes))
	unpaddedBytes = unpadBytes(paddedBytes, 16)
	print("Unpadded bytes: " + str(unpaddedBytes))