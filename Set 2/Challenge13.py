# solution to http://cryptopals.com/sets/2/challenges/13
# injection into ciphered bytes, encrypted in AES ECB mode

from Crypto.Cipher import AES
from random import randint

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(randint(0, 255))
	return randomBytes

# set blockLength to 16 for now
blockLength = 16
# generate unknown random key as a global
randomKey = randomByteGen(blockLength)

# padBytes takes a bytearray of bytes to pad, as well as a block size to pad to
# returns a bytearray of padded bytes
def padBytes(bytesToPad, blockSize):
	numPadBytes = blockSize - (len(bytesToPad) % blockSize)
	paddedBytes = bytesToPad
	for i in range(0, numPadBytes):
		paddedBytes.append(4)
	return paddedBytes
	
# decrypts AES cipher in ECB mode.  arguments are cipherBytes (bytes) and key (bytes)
# returns plaintext (bytes)
def decryptAES_ECB(cipherBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.decrypt(cipherBytes)

# encrypts AES cipher in ECB mode.  arguments are plainBytes (bytes) and key (bytes)
# returns ciphertext (bytes)
def encryptAES_ECB(plainBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.encrypt(plainBytes)
	
# given an email address (string), generates an encoded, ciphered string of data
# returns encoded ciphertext (bytes)
def getEncodedProfile(emailAddress):
	# clean encoding metacharacters '&' and '=' from email address
	cleanedEmail = emailAddress.replace("&", "").replace("=", "")
	encodedPlainString = "email=" + cleanedEmail + "&uid=10&role=user"
	# encrypt encoded plaintext string to encoded ciphertext bytes
	encodedPlainBytes = padBytes(bytearray(encodedPlainString, "ascii"), blockLength)
	encodedCipherBytes = encryptAES_ECB(bytes(encodedPlainBytes), bytes(randomKey))
	return encodedCipherBytes

# parses a string of the format "key1=value1&key2=value2&...".  takes the string as an argument
# returns dictionary of key / value pairs (string, string)
def parseKeyValue(encodedCipherBytes):
	# decrypt encoded ciphertext bytes to encoded plaintext string
	encodedPlainBytes = decryptAES_ECB(encodedCipherBytes, bytes(randomKey))
	encodedString = encodedPlainBytes.decode("ascii")
	# remove padding from end of string, and split into list of key/value pair entries
	pairList = encodedString.split("\x04")[0].split("&")
	entries = {}
	for entry in pairList:
		key = entry.split("=")[0]
		value = entry.split("=")[1]
		entries[key] = value
	return entries
	
	
#      above this line: setting up the problem
#-----------------------------------------------------
#       below this line: solving the problem
	
if __name__ == "__main__":
	givenEmail = ""
	print("Creating user with email address \"" + givenEmail + "\"")
	encodedKeyVals = getEncodedProfile(givenEmail)
	print("Encoded key/value pairs (encrypted): " + str(encodedKeyVals))
	keyVals = parseKeyValue(encodedKeyVals)
	print("Key/value pairs: " + str(keyVals))