# from Set 2/Challenge 15
# PKCS#7 padding utilities

# padBytes takes a bytearray of bytes to pad, as well as a block size to pad to
# returns padded bytes (bytearray)
def padBytes(bytesToPad, blockSize):
	numPadBytes = blockSize - (len(bytesToPad) % blockSize)
	paddedBytes = bytearray(bytesToPad)
	for i in range(0, numPadBytes):
		paddedBytes.append(numPadBytes)
	return paddedBytes

# verifyPadding verifies if a bytearray is padded with valid PKCS#7 padding
# returns nothing if padded correctly, and throws exception if not
def verifyPadding(paddedBytes, blockSize):
	numPadBytes = paddedBytes[-1]
	if numPadBytes not in range(1, blockSize+1):
		raise ValueError("The final byte's value " + str(numPadBytes) + " is greater than the block size " + str(blockSize))
	for i in range(0, numPadBytes):
		if paddedBytes[-(i+1)] != numPadBytes:
			raise ValueError("Byte at index " + str(-(i+1)) + " in final block is " + str(paddedBytes[-(i+1)]) + ", expected " + str(numPadBytes))
	return

# unpadBytes takes a bytearray of padded bytes, verifies it has valid padding, and strips the padding off
# returns unpadded bytes (bytearray) - throws exception if not padded correctly
def unpadBytes(bytesToUnpad, blockSize):
	verifyPadding(bytesToUnpad, blockSize)
	numToUnpad = bytesToUnpad[-1]
	unpadded = bytearray(bytesToUnpad)
	for i in range(0, numToUnpad):
		unpadded = unpadded[:-1]
	return unpadded