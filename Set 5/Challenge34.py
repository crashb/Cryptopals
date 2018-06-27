# solution to http://cryptopals.com/sets/5/challenges/34
# MITM key-fixing attack on DH with parameter injection

import random
import hashlib
import Challenge33
import AESUtils
import PaddingUtils

p = Challenge33.p
g = Challenge33.g

# generates a random sequence of bytes.  length is determined by length argument (int).
# returns randomBytes (bytearray)
def randomByteGen(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
	return randomBytes

# a class representing our user
class userSim:
	def __init__(self):
		# user starts with typical values of p and g
		self.p = p
		self.g = g
		# generate private and public keys
		self.a = random.randint(0, self.p - 1)
		self.A = Challenge33.GetPublicKey(self.p, self.g, self.a)
	def startHandshake(self, echoer):
		# establish references
		self.echoer = echoer
		self.echoer.user = self
		# pass p, g, and A to echo bot
		self.echoer.p = self.p
		self.echoer.g = self.g
		self.echoer.A = self.A
	def calcKey(self):
		keyHash = Challenge33.GetSharedKey(self.p, self.B, self.a)
		self.key = bytearray.fromhex(keyHash)[0:16]
	def sendMessage(self, message):
		paddedMessage = PaddingUtils.padBytes(message, 16)
		iv = randomByteGen(16)
		# pass ciphertext and IV to echoer
		self.echoer.encryptedMsg = AESUtils.encryptAES_CBC(paddedMessage, self.key, iv)
		self.echoer.ivFromUser = iv
	def decryptMessage(self, encryptedBytes):
		return AESUtils.decryptAES_CBC(encryptedBytes, self.key, self.ivFromEcho)
	def readEchoedMessage(self):
		decrypted = self.decryptMessage(self.encryptedEcho)
		return PaddingUtils.unpadBytes(decrypted, 16)
		
# a class representing our echo bot
class echoSim:
	def endHandshake(self):
		# generate private and public keys
		self.b = random.randint(0, self.p - 1)
		self.B = Challenge33.GetPublicKey(self.p, self.g, self.b)
		# pass B to user
		self.user.B = self.B
	def calcKey(self):
		keyHash = Challenge33.GetSharedKey(self.p, self.A, self.b)
		self.key = bytearray.fromhex(keyHash)[0:16]
	def decryptMessage(self, encryptedBytes):
		return AESUtils.decryptAES_CBC(encryptedBytes, self.key, self.ivFromUser)
	def echoMessage(self):
		decrypted = self.decryptMessage(self.encryptedMsg)
		iv = randomByteGen(16)
		# pass ciphertext and IV to user
		self.user.encryptedEcho = AESUtils.encryptAES_CBC(decrypted, self.key, iv)
		self.user.ivFromEcho = iv
		
# a class representing our nefarious 3rd party, who intercepts the ciphertexts,
# iv's, and tricks the user and echo into replacing their A and B values with p.
# this replacement causes the key value to be 0 - so our MITM knows the key, and
# can then read the messages between our user and our bot!
class mitmSim:
	def relayStartHandshake(self, echoer):
		# establish references
		self.echoer = echoer
		self.echoer.user = self
		# pass p, g, and p to echo bot
		self.echoer.p = self.p
		self.echoer.g = self.g
		self.echoer.A = self.p
	def relayEndHandshake(self):
		# pass p to user
		self.user.B = p
	def calcKey(self):
		# since we are passing p instead of A and B, the shared secret
		# value S will always be 0 (a^b mod a = 0 for any ints a and b)
		keyHash = hashlib.sha1('0'.encode('utf-8')).hexdigest()
		self.key = bytearray.fromhex(keyHash)[0:16]
	def readMessage(self, encryptedBytes, iv):
		decrypted = AESUtils.decryptAES_CBC(encryptedBytes, self.key, iv)
		decrypted = PaddingUtils.unpadBytes(decrypted, 16)
		print(decrypted.decode('utf-8'))
	def relaySendMessage(self):
		print("Message intercepted from user to bot:")
		self.readMessage(self.encryptedMsg, self.ivFromUser)
		# pass message and iv to actual echo bot
		self.echoer.encryptedMsg = self.encryptedMsg
		self.echoer.ivFromUser = self.ivFromUser
	def relayEchoMessage(self):
		print("Message intercepted from bot to user:")
		self.readMessage(self.encryptedEcho, self.ivFromEcho)
		# pass message and iv back to actual user
		self.user.encryptedEcho = self.encryptedEcho
		self.user.ivFromEcho = self.ivFromEcho

def connSetup(user, echo):
	user.startHandshake(echo)
	echo.endHandshake()
	user.calcKey()
	echo.calcKey()
	
def messageEcho(user, echo):
	print("Enter a message to be echoed:")
	message = bytes(input(), 'utf-8')
	user.sendMessage(message)
	echo.echoMessage()
	echoedMsg = user.readEchoedMessage()
	print("Echoed message:")
	print(echoedMsg.decode('utf-8'))
	
def demoProtocol():
	user = userSim()
	echo = echoSim()
	connSetup(user, echo)
	messageEcho(user, echo)
	
def connSetupMITM(user, mitm, echo):
	user.startHandshake(mitm)
	mitm.relayStartHandshake(echo)
	echo.endHandshake()
	mitm.relayEndHandshake()
	user.calcKey()
	mitm.calcKey()
	echo.calcKey()
	
def messageEchoMITM(user, mitm, echo):
	print("Enter a message to be echoed:")
	message = bytes(input(), 'utf-8')
	user.sendMessage(message)
	mitm.relaySendMessage()
	echo.echoMessage()
	mitm.relayEchoMessage()
	echoedMsg = user.readEchoedMessage()
	print("Echoed message:")
	print(echoedMsg.decode('utf-8'))
	
def mitmProtocol():
	user = userSim()
	mitm = mitmSim()
	echo = echoSim()
	connSetupMITM(user, mitm, echo)
	messageEchoMITM(user, mitm, echo)
	
if __name__ == "__main__":
	# pick one of these 2:
	# demoProtocol()
	mitmProtocol()