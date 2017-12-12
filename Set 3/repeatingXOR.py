# from challenge 6
# solves repeating-key XOR cipher.  uses chi2 scores to detect plaintext

import base64
import binascii
import math

# frequencies of all english letters + space + neither letters nor a space (represented by "~")
englishLetterFreq = {'A': 0.0651738, 'B': 0.0124248, 'C': 0.0217339, 'D': 0.0349835, 'E': 0.1041442, 'F': 0.0197881,
					 'G': 0.0158610, 'H': 0.0492888, 'I': 0.0558094, 'J': 0.0009033, 'K': 0.0050529, 'L': 0.0331490,
					 'M': 0.0202124, 'N': 0.0564513, 'O': 0.0596302, 'P': 0.0137645, 'Q': 0.0008606, 'R': 0.0497563,
					 'S': 0.0515760, 'T': 0.0729357, 'U': 0.0225134, 'V': 0.0082903, 'W': 0.0171272, 'X': 0.0013692, 
					 'Y': 0.0145984, 'Z': 0.0007836, ' ': 0.1918182, '~': 0.0000001}

# countLetters takes a string of characters and returns a dictionary with the amount of each letter in the message
def countLetters(message):					 
	letterCount = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'E': 0, 'F': 0, 'G': 0,
				   'H': 0, 'I': 0, 'J': 0, 'K': 0, 'L': 0, 'M': 0, 'N': 0, 
				   'O': 0, 'P': 0, 'Q': 0, 'R': 0, 'S': 0, 'T': 0, 'U': 0, 
				   'V': 0, 'W': 0, 'X': 0, 'Y': 0, 'Z': 0, ' ': 0, '~': 0}
	for letter in message.upper():
		if letter in letterCount.keys():
			letterCount[letter] += 1
		else:
			# catch-all solution for non-letter or space characters
			letterCount["~"] += 1
	return letterCount

# messageFrequency takes a string of characters and returns a dictionary with the frequency of each letter
def messageFrequency(message):
	letterCount = countLetters(message)
	letterFrequencies = {}
	for letter in letterCount:
		letterFrequencies[letter] = letterCount[letter] / sum(letterCount.values())
		# print("letterFrequencies[" + letter + "] = " + str(letterFrequencies[letter]))
	return letterFrequencies
	
# getChi2 gets the Chi2 score of a message string (returns float).  a lower Chi2 score indicates a higher likelihood of plaintext
def getChi2(message):
	letterFrequencies = messageFrequency(message)
	chi2 = 0
	for letter in letterFrequencies:
		difference = letterFrequencies[letter] - englishLetterFreq[letter]
		chi2 += difference*difference / englishLetterFreq[letter]
	return chi2

# singleByteXOR performs the single-byte XOR operation on a byte array xorBytes with a supplied key
# returns a byte array
def singleByteXOR(xorBytes, key):
	xorResult = bytearray()
	for byte in xorBytes:
		xorResult.append(byte ^ key)
	return xorResult

# singleByteXOR takes a bytearray of ciphertext and bruteforces the XOR cipher on it, using a Chi2 test on letter frequencies
# returns int key
def singleByteXORBF(cipherBytes):
	# print("Bruteforcing...")
	chiScores = {}
	for key in range(256):
		xorBytes = singleByteXOR(cipherBytes, key)
		xorResult = binascii.b2a_qp(xorBytes).decode("ascii")
		chiScores[key] = getChi2(xorResult)
		# print("XORing with " + str(key) + " yielded '" + xorResult[0:40] + "...' (Chi2: " + str(chiScores[key]) + ")")
	xorKey = min(chiScores, key=chiScores.get)
	# print("Best key is " + str(xorKey) + " with a Chi2 score of " + str(chiScores[xorKey]))
	plaintextBytes = singleByteXOR(cipherBytes, xorKey)
	# print("Plaintext characters: " + str(plaintextBytes) )
	# print("Letter Frequencies: " + str(messageFrequency(binascii.b2a_qp(plaintextBytes).decode("ascii"))))
	return xorKey
	
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

# popcount function: returns the number of on bits in a binary number
# from https://www.expobrain.net/2013/07/29/hamming-weights-python-implementation/
def popcount(x):
    x -= (x >> 1) & 0x5555555555555555
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
    return ((x * 0x0101010101010101) & 0xffffffffffffffff ) >> 56

# computes Hamming distance between two bytearrays.
# returns (int) Hamming distance
def hammingDistance(bytearray1, bytearray2):
	# ensure string lengths are equal
	if len(bytearray1) != len(bytearray2):
		print("Cannot compute Hamming distance: \"" + str(bytearray1) + "\" is not the same length as \"" + str(bytearray2) + "\"!")
		return -1
	xoredBytes = bytearray()
	for i in range(0, len(bytearray1)):
		xoredBytes.append(bytearray1[i] ^ bytearray2[i])
	distance = 0
	for b in xoredBytes:
		distance += popcount(b)
	return distance
	
# computes normalized Hamming distance between two bytearrays.
# returns (float) normalized Hamming distance
def normalizedHammingDistance(bytearray1, bytearray2):
	hDistance = hammingDistance(bytearray1, bytearray2)
	return hDistance / len(bytearray1)
	
# breaks repeating XOR on bytearray.  takes ciphered bytes as argument along with keysize to try.
# returns [plaintext bytes (bytearray), key bytes (bytearray)]
def breakRepeatingXOR(cipherBytes, keysize):
	print("Breaking repeating XOR cipher...")
	# break ciphertext into blocks of KEYSIZE length
	blocks = []
	numBlocks = int(math.ceil(len(cipherBytes)/keysize))
	for j in range(0, numBlocks):
		newBlock = cipherBytes[j*keysize:(j+1)*keysize]
		blocks.append(newBlock)
		
	# transpose all bytes to KEYSIZE different blocks
	# transposedBlocks[0] is made up of the first byte of every block, [1] is the second byte of every block...
	transposedBlocks = []
	for j in range(0, keysize):
		transposedBlocks.append(bytearray())	
	for block in blocks:
		for j in range(0, keysize):
			try:
				transposedBlocks[j].append(block[j])
			except (IndexError):
				# should only get here if at the end of the message
				pass
	
	# bruteforce single-byte XOR on all of the transposed blocks.  the byte value
	# that generates the best-looking histogram for the first block is the first
	# letter of the key, and so on...
	keyBytes = bytearray()
	for transposedBytes in transposedBlocks:
		keyBytes.append(singleByteXORBF(bytearray(transposedBytes)))
	plainBytes = repeatingKeyXOR(cipherBytes, keyBytes)
	
	return [plainBytes, keyBytes]
		
# TEST function for hamming distance.  should print 37
def hammingDistanceTest():
	print("Testing Hamming distance function...")
	string1 = "this is a test"
	string2 = "wokka wokka!!!"
	stringBytes1 = bytearray(string1, "ascii")
	stringBytes2 = bytearray(string2, "ascii")
	hDistance = hammingDistance(stringBytes1, stringBytes2)
	print("Hamming distance between \"" + string1 + "\" and \"" + string2 + "\": " + str(hDistance))

if __name__ == "__main__":
	with open('Challenge6Data.txt', 'r') as myfile:
		encryptedBytes = base64.b64decode(''.join(myfile.read().strip().split('\n')))
	breakRepeatingXOR(encryptedBytes, 1)