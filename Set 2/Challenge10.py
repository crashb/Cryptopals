# solution to http://cryptopals.com/sets/2/challenges/10
# implementation of AES CBC mode

import base64
from Crypto.Cipher import AES

# decrypts AES cipher in ECB mode.  arguments are cipherBytes (bytes) and key (bytes)
# returns plaintext (bytes)
def decryptAES_ECB(cipherBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.decrypt(cipherBytes)
	
# encrypts AES cipher in ECB mode.  arguments are plainBytes (bytes) and key (bytes)
# returns ciphertext (bytes)
def encryptAES_ECB(cipherBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.encrypt(cipherBytes)

# decrypts AES cipher in CBC mode.  chains together AES_ECB decryptions and XORs blocks together
# more information: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
# takes cipherBytes (bytearray), keyBytes (bytearray), and initialization vector bytes (bytearray)
# returns bytearray of decrypted bytes
def decryptAES_CBC(cipherBytes, keyBytes, IVBytes):
	numBlocks = int(len(cipherBytes) / len(keyBytes))
	xorBytes = IVBytes
	decrypted = bytearray()
	for i in range(0, numBlocks):
		encryptedBlock = cipherBytes[i*len(keyBytes):(i+1)*len(keyBytes)]
		nextXorBytes = encryptedBlock
		decryptedBlock = decryptAES_ECB(bytes(encryptedBlock), bytes(keyBytes))
		xoredBlock = fixedXOR(bytearray(decryptedBlock), xorBytes)
		decrypted += xoredBlock
		xorBytes = nextXorBytes
	return decrypted
	
# encrypts AES cipher in CBC mode.  chains together AES_ECB encryptions and XORs blocks together
# more information: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
# takes plainBytes (bytearray), keyBytes (bytearray), and initialization vector bytes (bytearray)
# returns bytearray of encrypted bytes
def encryptAES_CBC(plainBytes, keyBytes, IVBytes):
	numBlocks = int(len(plainBytes) / len(keyBytes))
	xorBytes = IVBytes
	encrypted = bytearray()
	for i in range(0, numBlocks):
		plainBlock = plainBytes[i*len(keyBytes):(i+1)*len(keyBytes)]
		xoredBlock = fixedXOR(plainBlock, xorBytes)
		encryptedBlock = encryptAES_ECB(bytes(xoredBlock), bytes(keyBytes))
		xorBytes = encryptedBlock
		encrypted += encryptedBlock
	return encrypted

# getEmptyIV is a function to return an empty initialization vector of a given length (int)
# returns bytearray of [0, 0, 0, ...]
def getEmptyIV(length):
	IV = bytearray();
	for i in range(0, length):
		IV.append(0)
	return IV

# XORs two bytearrays
# returns a bytearray that is the result of the operation
def fixedXOR(buffer1Bytes, buffer2Bytes):
	xorResultBytes = buffer1Bytes
	for index, byte in enumerate(buffer2Bytes):
		xorResultBytes[index] ^= byte
	return xorResultBytes
	
# tests the CBC encryption function by encrypting and decrypting a supplied plaintext string using a supplied key string
# prints encryption and decryption results
# returns nothing - only purpose is to print results
def testEncryptAES_CBC(plainString, keyString):
	print("Testing CBC mode encryption on string \"" + plainString + "\" with key \"" + keyString + "\"...")
	plainBytes = bytearray(plainString, "ascii")
	keyBytes = bytearray(keyString, "ascii")
	encryptedBytes = encryptAES_CBC(plainBytes, keyBytes, getEmptyIV(len(keyString)))
	print("Encrypted bytes:")
	print(str(encryptedBytes))
	decryptedBytes = decryptAES_CBC(encryptedBytes, keyBytes, getEmptyIV(len(keyString)))
	print("Decrypted bytes:")
	print(str(decryptedBytes))
	# check if we obtain the expected result
	if (decryptedBytes.decode("ascii") == plainString[0:len(decryptedBytes)]) and (decryptedBytes.decode("ascii") != ""):
		print("The decrypted string matches the supplied string - CBC mode is working!")
	else:
		print("The decrypted string does not match the supplied string - check the results manually.")
	return

if __name__ == "__main__":
	# read file into bytearray encryptedBytes
	with open('Challenge10Data.txt', 'r') as myfile:
		encryptedBytes = base64.b64decode(''.join(myfile.read().strip().split('\n')))
	keyBytes = bytearray("YELLOW SUBMARINE", "ascii")
	# create empty initialization vector
	emptyIV = getEmptyIV(len(keyBytes))
	decryptedBytes = decryptAES_CBC(encryptedBytes, keyBytes, emptyIV)
	print("Decrypted file: " + decryptedBytes.decode("ascii"))