# solution to http://cryptopals.com/sets/6/challenges/46
# RSA parity oracle

import RSAUtils
from base64 import b64decode

# decrypts RSA and returns plaintext parity
def checkParity(cipherInt, d, n):
	plainInt = pow(cipherInt, d, n)
	return plainInt % 2
	
# "doubles" an encrypted plaintext
def doubleCipherInt(cipherInt, e, n):
	return cipherInt * (2**e)
	
# decrypts from oracle.  private key d is only used by oracle
def decryptFromOracle(cipherInt, e, n, d):
	lowBound = 0
	highBound = n
	current = cipherInt
	while (highBound - lowBound) > 1:
		current = doubleCipherInt(current, e, n)
		if checkParity(current, d, n) == 0:
			highBound = highBound - (highBound - lowBound) // 2
		else:
			lowBound = lowBound + (highBound - lowBound) // 2
		# "hollywood-style" decryption
		print(highBound.to_bytes((highBound.bit_length() + 7) // 8, 'big'))
	# sometimes the last character will be off by one bit, no way for it to tell
	return lowBound
		
			
if __name__ == "__main__":
	secretMsg = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	e, n, d = RSAUtils.generateKey()
	plainInt = int.from_bytes(b64decode(secretMsg), 'big')
	cipherInt = pow(plainInt, e, n)
	plainInt = decryptFromOracle(cipherInt, e, n, d)
	print("Message decrypted:")
	print(plainInt.to_bytes((plainInt.bit_length() + 7) // 8, 'big').decode('utf-8'))