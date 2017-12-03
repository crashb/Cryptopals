# solution to http://cryptopals.com/sets/1/challenges/8
# detects AES in ECB mode

# getLinesFromFile takes a filepath as an argument, and returns the list of lines in the file
def getLinesFromFile(filePath):
	with open(filePath) as f:
		content = f.readlines()
	content = [x.strip() for x in content]
	return content

# detectECB takes a list of ciphertext strings in hex form, and returns the detected ciphertext
# in ECB mode, identical plaintext blocks are encrypted into identical ciphertext blocks
def detectECB(cipherList):
	for cipherText in cipherList:
		cipherBytes = bytearray.fromhex(cipherText)
		blocks = []
		for i in range(0, len(cipherBytes), 16):
			if cipherBytes[i:i+16] in blocks:
				return cipherText
			blocks.append(cipherBytes[i:i+16])

if __name__ == "__main__":
	cipherTextList = getLinesFromFile("Challenge8Data.txt")
	cipherText = detectECB(cipherTextList)
	if cipherText == None:
		print("No ciphertext found in file!")
	else:
		print("ECB detected in ciphertext: " + cipherText)