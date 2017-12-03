# solution to http://cryptopals.com/sets/2/challenges/9
# implementation of byte padding

# padBytes takes a bytearray of bytes to pad, as well as a block size to pad to
# returns a bytearray of padded bytes
def padBytes(bytesToPad, blockSize):
	numPadBytes = blockSize - (len(bytesToPad) % blockSize)
	paddedBytes = bytesToPad
	for i in range(0, numPadBytes):
		paddedBytes.append(4)
	return paddedBytes

if __name__ == "__main__":
	someBytes = bytearray("YELLOW SUBMARINE", "ascii")
	paddedBytes = padBytes(someBytes, 20)
	print("Padded bytes: " + str(paddedBytes))