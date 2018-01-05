# from Set 2/Challenge 10
# implementation of AES CBC mode

from Crypto.Cipher import AES

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
	xorResultBytes = bytearray(buffer1Bytes)
	for index, byte in enumerate(buffer2Bytes):
		xorResultBytes[index] ^= byte
	return xorResultBytes
	
# XORs two bytearrays
# returns a bytearray that is the result of the operation, length same length as first argument supplied
def streamXOR(dest, source):
	resultBytes = bytearray(dest)
	for i in range(0, len(dest)):
		resultBytes[i] ^= source[i]
	return resultBytes

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

# encrypts/decrypts AES in CTR mode.  the operation is symmetrical for encryption and decryption.
# returns bytearray
def cryptAES_CTR(startBytes, keyBytes, nonce):
	numBlocks = math.ceil(len(startBytes) / blockLength)
	counter = 0
	keyStream = bytearray()
	endBytes = bytearray()
	nonceBytes = struct.pack('<Q', nonce)
	for i in range(0, numBlocks):
		# pack counter int into 64-bit little endian format
		counterBytes = struct.pack('<Q', counter)
		# prepend nonceBytes to counter to create bytes that are then encrypted
		counterBytes = bytearray(nonceBytes) + counterBytes
		keyStream += encryptAES_ECB(bytes(counterBytes), bytes(keyBytes))
		counter += 1
	# xor our fully generated keyStream against startBytes all in one go
	resultBytes = streamXOR(startBytes, keyStream)
	return resultBytes