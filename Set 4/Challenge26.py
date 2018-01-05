# solution to http://cryptopals.com/sets/4/challenges/26
# CTR bitflipping attack

import AESUtils

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

# set blocklength to 16 - assume it is known
blockLength = 16
# generate unknown random key and nonce
randomKey = randomByteGen(16)
nonceBytes = randomByteGen(8)
randomNonce = struct.unpack('<Q', nonceBytes)[0]

# given an input string, generates an encoded, ciphered string of data
# returns encoded ciphertext (bytes)
def getEncodedProfile(inputString):
	# clean encoding metacharacters ';' and '=' from input string
	cleanedInput = inputString.replace(";", "").replace("=", "")
	encodedPlainString = "comment1=cooking MCs;userdata=" + cleanedInput + ";comment2= like a pound of bacon" 
	# encrypt encoded plaintext string to encoded ciphertext bytes
	encodedPlainBytes = padBytes(bytearray(encodedPlainString, "ascii"), blockLength)
	encodedCipherBytes = AESUtils.cryptAES_CTR(encodedPlainBytes, randomKey, randomNonce)
	return encodedCipherBytes

# decrypts provided bytes with CBC
# returns encoded plaintext (bytes)
def decryptProfile(cipherBytes):
	return AESUtils.cryptAES_CTR(cipherBytes, randomKey, randomNonce)
	
# given ciphered encoded bytes, decrypt them and check for string ";admin=true;"
# returns boolean
def checkAdmin(cipherBytes):
	plainBytes = decryptProfile(cipherBytes)
	print("Decrypted bytes: \n" + str(plainBytes))
	if bytearray(";admin=true;", "ascii") in plainBytes:
		print("Admin entry found!")
		return True
	else:
		print("Admin entry not found.")
		return False


if __name__ == "__main__":
	pass