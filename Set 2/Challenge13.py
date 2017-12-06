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
	
# test function that verifies the system is working with a given email (string)
# returns nothing - only purpose is to print information to the terminal
def testIntended(givenEmail):
	print("Creating user with email address \"" + givenEmail + "\"...")
	encodedKeyVals = getEncodedProfile(givenEmail)
	print("Encrypted encoded profile: " + str(encodedKeyVals))
	keyVals = parseKeyValue(encodedKeyVals)
	print("User profile: " + str(keyVals))
	return
	
	
#      above this line: setting up the problem
#-----------------------------------------------------
#       below this line: solving the problem

# to solve this problem, we are first going to supply the getEncodedProfile function
# with an email such that "email=...&uid=10&role=" is block-aligned.  for this exercise,
# we already know the block length is 16.  the next block will consist only of "user";
# once that is ciphered, it can be replaced with a ciphered block that consists only
# of "admin".

# gets the ciphered bytes of the profile that correspond to "email=...&uid=10&role="
# returns ciphered prefix (bytearray)
def getProfilePrefix():
	# the email address we supply will consist of all "a", and be of the length needed
	# to correctly align the plaintext within the last block of the cipher
	suppliedEmail = ""
	while ((len("email=") + (len(suppliedEmail)) + len("&uid=10&role=")) % blockLength) != 0:
		suppliedEmail += "a"
	# get an encoded profile, then delete the last full block to obtain the prefix bytes
	alignedBytes = getEncodedProfile(suppliedEmail)
	prefixBytes = alignedBytes[:-blockLength]
	return prefixBytes
	
# now that we have the ciphertext prefix, we want to find out the ciphertext that corresponds
# to "admin", then append it to the prefix.  to do this, we need to make a block in the middle
# of the supplied email address that contains "admin" + the necessary padding

# gets the ciphered bytes of the profile that correspond to "admin"
# returns ciphered postfix (bytearray)
def getProfilePostfix():
	# the email address we supply will consist of all "a" until we can start a new block
	suppliedEmail = ""
	while ((len("email=") + (len(suppliedEmail))) % blockLength) != 0:
		suppliedEmail += "a"
	# now we have started a new block in the plaintext, so we add "admin" along
	# with however much padding is required to complete the next block
	suppliedEmail += "admin"
	while ((len("email=") + (len(suppliedEmail))) % blockLength) != 0:
		suppliedEmail += "\x04"
	# the target block of the ciphertext is the second one, which consists of "admin" and padding
	alignedBytes = getEncodedProfile(suppliedEmail)
	postfixBytes = alignedBytes[blockLength:2*blockLength]
	return postfixBytes
	
if __name__ == "__main__":
	# first do a test to make sure the system is working as intended - make a normal user
	testIntended("foo@bar.com")
	# then create a user with role=admin by combining a prefix and a postfix generated by the oracle
	print("Creating user with role=admin...")
	prefixBytes = getProfilePrefix()
	postfixBytes = getProfilePostfix()
	moddedCipherBytes = prefixBytes + postfixBytes
	print("Modified encrypted encoded profile: " + str(moddedCipherBytes))
	profile = parseKeyValue(moddedCipherBytes)
	print("User profile: " + str(profile))