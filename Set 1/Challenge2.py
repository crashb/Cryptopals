# solution to http://cryptopals.com/sets/1/challenges/2
# fixed XOR cipher

import binascii

def fixedXOR(buffer1, buffer2):
	buffer1Bytes = bytearray.fromhex(buffer1)
	buffer2Bytes = bytearray.fromhex(buffer2)
	xorResultBytes = buffer1Bytes
	for index, byte in enumerate(buffer2Bytes):
		xorResultBytes[index] ^= byte
	xorResult = binascii.hexlify(xorResultBytes).decode("ascii")
	return xorResult
	
if __name__ == "__main__":
	buffer1 = "1c0111001f010100061a024b53535009181c"
	buffer2 = "686974207468652062756c6c277320657965"
	xorResult = fixedXOR(buffer1, buffer2)
	print("Input 1: " + buffer1)
	print("Input 2: " + buffer2)
	print("Output:  " + xorResult)