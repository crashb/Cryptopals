# solution to http://cryptopals.com/sets/1/challenges/7
# decodes AES-128 in ECB mode

import base64
from Crypto.Cipher import AES

# decrypts AES cipher in ECB mode.  arguments are cipherBytes (bytes) and key (bytes)
# CANNOT use mutable type bytearray; only byte strings can be passed to C code
# returns plaintext (bytes)
def decryptAES(cipherBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.decrypt(cipherBytes)

if __name__ == "__main__":
	with open('Challenge7Data.txt', 'r') as myfile:
		encryptedBytes = base64.b64decode(''.join(myfile.read().strip().split('\n')))
	keyBytes = b"YELLOW SUBMARINE"
	print("Decrypting with key " + keyBytes.decode("ascii") + "...")
	plainBytes = decryptAES(encryptedBytes, keyBytes)
	print("Plaintext: " + plainBytes.decode("ascii"))