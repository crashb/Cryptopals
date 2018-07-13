# solution to http://cryptopals.com/sets/6/challenges/41
# Implement unpadded message recovery oracle

import RSAUtils
import time
import hashlib

def SHA256(s):
	return hashlib.sha256(s.encode('utf-8')).hexdigest()
	
# given an input message, construct the plaintext blob
def makeBlob(msg):
	timeStamp = int(time.time())
	return "time: " + str(timeStamp) + ", msg: " + msg

# a class representing our server
class serverSim():
	# initialize the server and publish the public key
	def __init__(self):
		self.deadHashes = []
		self.e, self.n, self.d = RSAUtils.generateKey()
	# check if this ciphertext has already been received
	def isLive(self, cipherInt):
		cipherHash = SHA256(str(cipherInt))
		if cipherHash in self.deadHashes:
			return False
		else:
			self.deadHashes.append(cipherHash)
			return True
	# show the plaintext bytes given a ciphertext int
	def showPlaintext(self, cipherInt):
		if not self.isLive(cipherInt):
			return "ERROR - cipher already received!"
		else:
			return RSAUtils.decrypt(cipherInt, self.d, self.n)
	
if __name__ == "__main__":
	# get public key from server
	server = serverSim()
	e = server.e
	n = server.n
	# get desired plaintext from user
	print("Enter a message: ")
	msg = input()
	msgBlob = makeBlob(msg)
	cipherInt = RSAUtils.encrypt(msgBlob, e, n)
	# user sends blob to server to decrypt
	result = server.showPlaintext(cipherInt)
	print(str(result))
	
	# sending the ciphertext again will not work
	# result = server.showPlaintext(cipherInt)
	# print(str(result))
	
	# the attacker modifies the ciphertext
	s = n
	while not RSAUtils.checkRelativelyPrime(s, n):
		s = RSAUtils.getPrime()
	cMod = (pow(s, e, n) * cipherInt) % n
	# attacker sends modified ciphertext to server to get modified plaintext
	pModBytes = server.showPlaintext(cMod)
	pMod = int.from_bytes(pModBytes, byteorder='big', signed=False)
	# unmodify returned plaintext
	p = (pMod * RSAUtils.invmod(s, n)) % n
	cracked = p.to_bytes((p.bit_length() + 7) // 8, byteorder='big')
	print("Message cracked: " + str(cracked))
	
	