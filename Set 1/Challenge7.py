# solution to http://cryptopals.com/sets/1/challenges/7
# decodes AES-128 in ECB mode

import base64
from Crypto.Cipher import AES

# decrypts AES cipher.  arguments are cipherBytes (bytearray) and key (bytearray)
# returns bytearray in plaintext
def decryptAES(cipherBytes, keyBytes):
	cipher = AES.new(keyBytes, AES.MODE_ECB)
	return cipher.decrypt(cipherBytes)

if __name__ == "__main__":
	key = "YELLOW SUBMARINE"
	with open('Challenge7Data.txt', 'r') as myfile:
		encryptedBytes = base64.b64decode(''.join(myfile.read().strip().split('\n')))
	keyBytes = byteArray(key)
	print("Decrypting with key " + key + "...")
	plainBytes = decryptAES(encryptedBytes, keyBytes)
	print("Plaintext: " + plainBytes.decode("ascii"))