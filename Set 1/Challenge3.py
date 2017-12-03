# solution to http://cryptopals.com/sets/1/challenges/3
# brute-forces single-byte XOR cipher - uses chi2 scores to detect plaintext

import binascii

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
	
# getChi2 gets the Chi2 score of a message.  a lower Chi2 score indicates a higher likelihood of plaintext
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

# singleByteXOR takes a string of hex and bruteforces the XOR cipher on it, using a Chi2 test on letter frequencies
# returns a plaintext byte array
def singleByteXORBF(hexString):
	cipherBytes = bytearray.fromhex(hexString)
	print("Bruteforcing...")
	chiScores = {}
	for key in range(256):
		xorBytes = singleByteXOR(cipherBytes, key)
		xorResult = binascii.b2a_qp(xorBytes).decode("ascii")
		chiScores[key] = getChi2(xorResult)
		# print("XORing with " + str(key) + " yielded '" + xorResult + "' (Chi2: " + str(chiScores[key]) + ")")
	xorKey = min(chiScores, key=chiScores.get)
	print("Best key is " + str(xorKey) + " with a Chi2 score of " + str(chiScores[xorKey]))
	return singleByteXOR(cipherBytes, xorKey)
	

if __name__ == "__main__":
	cipherHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	# Challenge 4 debug:
	# cipherHex = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
	print("Ciphered Hex: " + cipherHex)
	resultHex = singleByteXORBF(cipherHex)
	result = binascii.b2a_qp(resultHex).decode("ascii")
	print("Plaintext: " + result)