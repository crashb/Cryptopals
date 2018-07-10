# solution to http://cryptopals.com/sets/5/challenges/38
# Offline dictionary attack on simplified SRP

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
		# send I to server
		self.server.I = self.I
	def sendA(self):
		# generate private a and public A
		self.a = random.randint(0, self.N - 1)
		self.A = pow(self.g, self.a, self.N)
		self.server.A = self.A
	def KCalc(self):
		# calculate and store K value
		xH = SHA256(str(self.salt) + self.P)
		x = int(xH, 16)
		S = pow(self.B, self.a + self.u * x, self.N)
		self.K = SHA256(str(S))
	def sendHMAC(self):
		# compute HMAC and send to server
		self.hmac = HMAC_SHA256(self.K, self.salt)
		self.server.clientHMAC = self.hmac

# a class representing our server
class serverSim:
	def __init__(self):
		# setup valid accounts on server
		self.logins = {}
		self.logins["me@me.me"] = "my password"
		self.logins["admin"] = "pikachu" # easy to brute-force
	def setup(self):
		# store N, g, k, I
		self.N = N
		self.g = g
		self.k = k
		# find out corresponding password from email
		try:
			self.P = self.logins[self.I]
		except KeyError:
			self.P = ""
			print("No password on record for \"" + email + "\"")
		# generate v with random salt
		self.salt = random.randint(0, 256)
		xH = SHA256(str(self.salt) + self.P)
		x = int(xH, 16)
		self.v = pow(self.g, x, self.N)
	def sendB(self):
		# generate private b, public B, random u
		self.b = random.randint(0, self.N - 1)
		self.B = pow(self.g, self.b, self.N)
		self.u = random.getrandbits(128)
		# send salt, B, and u to client
		self.client.salt = self.salt
		self.client.B = self.B
		self.client.u = self.u
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
			
# a class representing our MITM - impersonating our server
class middleSim:
	def setup(self):
		# store N, g, k, I
		self.N = N
		self.g = g
		self.k = k
		# we don't know the password to begin with, so we can't get v
	def sendB(self):
		# set arbitrary salt, b, and u
		self.salt = 1
		self.b = 2
		self.B = pow(self.g, self.b, self.N)
		self.u = 3
		# send arbitrary B, U, and salt to client
		self.client.salt = self.salt
		self.client.B = self.B
		self.client.u = self.u
	def bruteforceHMAC(self):
		f = open('Wordlist.txt', 'r')
		for l in f.readlines():
			line = l.strip()
			# calculate v
			xH = SHA256(str(self.salt) + line)
			x = int(xH, 16)
			self.v = pow(self.g, x, self.N)
			# calculate K
			S = pow(self.A * pow(self.v, self.u, self.N), self.b, self.N)
			self.K = SHA256(str(S))
			# calculate HMAC
			self.serverHMAC = HMAC_SHA256(self.K, self.salt)
			if self.serverHMAC == self.clientHMAC:
				print("Password cracked: " + line)
				return
	
		print("Password could not be cracked with the provided wordlist!")
		return
	
# execute the SRP protocol
def SRPProtocol(client, server, email, password):
	client.setup(server, email, password)
	server.setup()
	client.sendA()
	server.sendB()
	client.KCalc()
	server.KCalc()
	client.sendHMAC()
	server.checkHMAC()
	
# execute the protocol with a man in the middle instead of the server
def MITMProtocol(client, middle, email, password):
	client.setup(middle, email, password)
	middle.setup()
	client.sendA()
	middle.sendB()
	client.KCalc()
	client.sendHMAC()
	middle.bruteforceHMAC()
	
# demo the SRP protocol working as intended
def demoProtocol(email, password):
	client = clientSim()
	server = serverSim()
	SRPProtocol(client, server, email, password)
	
# demo the SRP protocol working with a man in the middle
def demoMITM(email, password):
	client = clientSim()
	middle = middleSim()
	MITMProtocol(client, middle, email, password)
	
if __name__ == "__main__":
	print("Enter your email: ")
	email = input()
	print("Enter your password: ")
	password = input()
	
	# demoProtocol(email, password)
	demoMITM(email, password)