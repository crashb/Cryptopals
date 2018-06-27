# solution to http://cryptopals.com/sets/5/challenges/35
# Implement DH with negotiated groups, and break with malicious "g" parameters

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
	def sendNegotiation(self, echoer):
		# establish references
		self.echoer = echoer
		self.echoer.user = self
		# pass p and g to echo bot
		self.echoer.p = self.p
		self.echoer.g = self.g
	def sendUserPub(self):
		# generate private and public keys
		self.a = random.randint(0, self.p - 1)
		self.A = Challenge33.GetPublicKey(self.p, self.g, self.a)
		# pass A to echo bot
		self.echoer.A = self.A
	def calcSharedKey(self):
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
	def sendAck(self):
		# after sending modified g, force both parties to use it.
		# https://www.reddit.com/r/crypto/comments/4z9xy2/help_with_cryptopals_set_5diffie_hellman/
		self.user.p = self.p
		self.user.g = self.g
	def sendEchoPub(self):
		# generate private and public keys
		self.b = random.randint(0, self.p - 1)
		self.B = Challenge33.GetPublicKey(self.p, self.g, self.b)
		# pass B to user
		self.user.B = self.B
	def calcSharedKey(self):
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
		
# implementation of generic MITM class, used for all 3 g values.
class mitmGeneric:
	def relayAck(self):
		# relay modified ack
		self.user.p = self.p
		self.user.g = self.g
	def relayUserPub(self):
		self.echoer.A = self.A
	def relayEchoPub(self):
		self.user.B = self.B
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
		
class mitm1(mitmGeneric):
	def relayNegotiation(self, echoer):
		# establish references
		self.echoer = echoer
		self.echoer.user = self
		# pass real p and g = 1 to bot
		self.echoer.p = self.p
		self.echoer.g = 1
	def calcSharedKey(self):
		# we pass g as 1, and 1 to any power is simply 1, so the shared
		# secret S will always be 1
		keyHash = hashlib.sha1('1'.encode('utf-8')).hexdigest()
		self.key = bytearray.fromhex(keyHash)[0:16]
		
class mitm2(mitmGeneric):
	def relayNegotiation(self, echoer):
		# establish references
		self.echoer = echoer
		self.echoer.user = self
		# pass real p and g = p to bot
		self.echoer.p = self.p
		self.echoer.g = self.p
	def calcSharedKey(self):
		# g = p, so key will be 0, same as Challenge34
		keyHash = hashlib.sha1('0'.encode('utf-8')).hexdigest()
		self.key = bytearray.fromhex(keyHash)[0:16]
		
class mitm3(mitmGeneric):
	def relayNegotiation(self, echoer):
		# establish references
		self.echoer = echoer
		self.echoer.user = self
		# pass real p and g = p - 1 to bot
		self.echoer.p = self.p
		self.echoer.g = self.p - 1
	def calcSharedKey(self):
		# when g = p - 1, A and B are both either equal to 1 or p - 1.
		# when both are p - 1, key is p - 1.  otherwise, key is 1.
		if (self.A == self.p-1) and (self.B == self.p-1):
			keyHash = hashlib.sha1(str(self.p-1).encode('utf-8')).hexdigest()
			self.key = bytearray.fromhex(keyHash)[0:16]
		else:
			keyHash = hashlib.sha1('1'.encode('utf-8')).hexdigest()
			self.key = bytearray.fromhex(keyHash)[0:16]

def connSetup(user, echo):
	user.sendNegotiation(echo)
	echo.sendAck()
	user.sendUserPub()
	echo.sendEchoPub()
	# both parties calculate their shared key
	user.calcSharedKey()
	echo.calcSharedKey()
	
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
	user.sendNegotiation(mitm)
	mitm.relayNegotiation(echo)
	echo.sendAck()
	mitm.relayAck()
	user.sendUserPub()
	mitm.relayUserPub()
	echo.sendEchoPub()
	mitm.relayEchoPub()
	# all 3 parties calculate the shared key
	user.calcSharedKey()
	mitm.calcSharedKey()
	echo.calcSharedKey()
	
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
	
def mitmProtocol1():
	user = userSim()
	mitm = mitm1()
	echo = echoSim()
	connSetupMITM(user, mitm, echo)
	messageEchoMITM(user, mitm, echo)
	
def mitmProtocol2():
	user = userSim()
	mitm = mitm2()
	echo = echoSim()
	connSetupMITM(user, mitm, echo)
	messageEchoMITM(user, mitm, echo)

def mitmProtocol3():
	user = userSim()
	mitm = mitm3()
	echo = echoSim()
	connSetupMITM(user, mitm, echo)
	messageEchoMITM(user, mitm, echo)
	
if __name__ == "__main__":
	# demoProtocol()
	print("Testing with g = 1...")
	mitmProtocol1()
	print("Testing with g = p...")
	mitmProtocol2()
	print("Testing with g = p - 1...")
	mitmProtocol3()