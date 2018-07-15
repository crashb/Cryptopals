# solution to http://cryptopals.com/sets/6/challenges/45
# DSA parameter tampering

import random
import hashlib
from Crypto.Util import number
import Challenge43

p = Challenge43.p
q = Challenge43.q

# calculate SHA1 digest bytes for a given string
def SHA1(s):
	return hashlib.sha1(s.encode('utf-8')).digest()

# modified version of DSA key generation and signing with an argument for g
def getKeys(g):
	x = random.randint(0, q) # choose a random private key
	y = pow(g, x, p)         # calculate public key
	return (x, y)
	
# sign a message with a custom g and private key
def signDSA(m, g, x):
	while True:
		k = random.randint(0, q)
		k_inv = Challenge43.invmod(k, q)
		r = pow(g, k, p) % q
		if r == 0 and g != 0: # allow r = 0 when g = 0
			continue
		hashInt = int.from_bytes(SHA1(m), byteorder='big')
		s = (k_inv * (hashInt + x*r)) % q
		if s == 0:
			continue
		return (r, s)
		
# verify a message's private key and signature with its public key
def verifyDSA(m, g, y, r, s):
	w = Challenge43.invmod(s, q)
	hashInt = int.from_bytes(SHA1(m), byteorder='big')
	u_1 = (hashInt * w) % q
	u_2 = (r * w) % q
	v = ((pow(g, u_1, p) * pow(y, u_2, p)) % p) % q
	return (v == r)
	
# test signing and verification functions for g = 0
def testG0():
	print("Testing g = 0...")
	g = 0
	print("Enter a message to sign:")
	msg = input()
	x, y = getKeys(g)
	r, s = signDSA(msg, g, x)
	if verifyDSA(msg, g, y, r, s):
		print("Signature verified!")
	else:
		print("Invalid signature.")
		
def magicSig(y):
	z = number.getPrime(256)
	r = pow(y, z, p) % q
	z_inv = Challenge43.invmod(z, q)
	s = (r * z_inv) % q
	return (r, s)
	
def testMagicSig(msg):
	g = p + 1
	x, y = getKeys(g)
	r, s = magicSig(y)
	if verifyDSA(msg, g, y, r, s):
		print("Signature verified for message '" + msg + "'")
	else:
		print("Invalid signature.")

if __name__ == "__main__":
	testG0()
	print("Testing 'magic signature' for g = p + 1...")
	testMagicSig("Hello, world")
	testMagicSig("Goodbye, world")