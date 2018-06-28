# solution to http://cryptopals.com/sets/5/challenges/36
# Implement Secure Remote Password (SRP)

import random
import hashlib

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

def SHA256(s):
	return hashlib.sha256(s.encode('utf-8')).hexdigest()
	
blockSize = 32	

# XORs two bytearrays
# returns a bytearray that is the result of the operation, length same length as first argument supplied
def streamXOR(dest, source):
	resultBytes = bytearray(dest)
	for i in range(0, len(dest)):
		resultBytes[i] ^= source[i]
	return resultBytes

# given a value and salt, get HMAC-SHA256
def HMAC_SHA256(value, key):
	keyBytes = bytearray(key)
	# keys longer than blockSize are shortened by hashing them
	if(len(keyBytes) > blockSize):
		keyBytes = bytearray.fromhex(SHA256(str(keyBytes)))
	
	# pad key with 0 to make it blockSize bytes long
	if(len(keyBytes) < blockSize):
		for i in range(0, blockSize - len(keyBytes)):
			keyBytes.append(0)
	
	o_key_pad = streamXOR(keyBytes, b'\x5c' * blockSize) # outer padded key
	i_key_pad = streamXOR(keyBytes, b'\x36' * blockSize) # inner padded key
	
	fileBytes = bytearray(value, "ascii")
	innerHash = bytearray.fromhex(SHA256(str(i_key_pad + fileBytes)))
	return SHA256(str(o_key_pad + innerHash))

# a class representing our client
class clientSim:
	def setup(self, server, email, password):
		# establish references
		self.server = server
		self.server.client = self
		# store N, g, k, I, P
		self.N = N
		self.g = g
		self.k = k
		self.I = email
		self.P = password
	def sendA(self):
		# generate private a and public A
		self.a = random.randint(0, self.N - 1)
		self.A = pow(self.g, self.a, self.N)
		# send I, A to server
		# I does not actually need to be sent here, since 
		# we assume the server already knows I for convenience.
		self.server.I = self.I
		self.server.A = self.A
	def uCalc(self):
		# calculate and store u value
		uH = SHA256(str(self.A) + str(self.B))
		self.u = int(uH, 16)
	def KCalc(self):
		# calculate and store K value
		xH = SHA256(str(self.salt) + self.P)
		x = int(xH, 16)
		S = pow(self.B - self.k * pow(self.g, x, self.N), self.a + self.u * x, self.N)
		self.K = SHA256(str(S))
	def sendHMAC(self):
		# compute HMAC and send to server
		self.hmac = HMAC_SHA256(self.K, self.salt)
		self.server.clientHMAC = self.hmac
	
# a class representing our server
class serverSim:
	def setup(self, email, password):
		# store N, g, k, I, P
		self.N = N
		self.g = g
		self.k = k
		self.I = email
		self.P = password
		# generate v with random salt
		self.salt = random.randint(0, 256)
		xH = SHA256(str(self.salt) + self.P)
		x = int(xH, 16)
		self.v = pow(self.g, x, self.N)
	def sendB(self):
		# generate private b and public B
		self.b = random.randint(0, self.N - 1)
		self.B = (self.k*self.v) + pow(self.g, self.b, self.N)
		# send salt and B to client
		self.client.salt = self.salt
		self.client.B = self.B
	def uCalc(self):
		# calculate and store u value
		uH = SHA256(str(self.A) + str(self.B))
		self.u = int(uH, 16)
	def KCalc(self):
		# calculate and store K value
		S = pow(self.A * pow(self.v, self.u, self.N), self.b, self.N)
		self.K = SHA256(str(S))
	def checkHMAC(self):
		self.serverHMAC = HMAC_SHA256(self.K, self.salt)
		if self.serverHMAC == self.clientHMAC:
			print("HMAC valid!")
		else:
			print("HMAC invalid!")
		
def demoProtocol(email, password):
	client = clientSim()
	server = serverSim()
	client.setup(server, email, password)
	server.setup(email, password)
	client.sendA()
	server.sendB()
	client.uCalc()
	server.uCalc()
	client.KCalc()
	server.KCalc()
	client.sendHMAC()
	server.checkHMAC()
	
if __name__ == "__main__":
	print("Enter your email: ")
	email = input()
	print("Enter your password: ")
	password = input()
	demoProtocol(email, password)