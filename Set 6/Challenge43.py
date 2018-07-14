# solution to http://cryptopals.com/sets/6/challenges/43
# DSA key recovery from nonce

import random
import hashlib

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
 
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
 
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

# calculate SHA1 digest bytes for a given string
def SHA1(s):
	return hashlib.sha1(s.encode('utf-8')).digest()
	
# calculate extended greatest common denominator of a and b
def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	g, y, x = egcd(b%a,a)
	return (g, x - (b//a) * y, y)

# calculate modular inverse of a mod m
def invmod(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('No modular inverse')
	return x % m
	
# get private key x and public key y from params
def getKeys():
	x = random.randint(0, q) # choose a random private key
	y = pow(g, x, p)         # calculate public key
	return (x, y)
	
# sign a message with a private key
def signDSA(m, x):
	while True:
		k = random.randint(0, q)
		k_inv = invmod(k, q)
		r = pow(g, k, p) % q
		if r == 0:
			continue
		hashInt = int.from_bytes(SHA1(m), byteorder='big')
		s = (k_inv * (hashInt + x*r)) % q
		if s == 0:
			continue
		return (r, s)
		
# sign a message with a private key with a given nonce
def signWithK(m, x, k):
	try:
		k_inv = invmod(k, q)
	except:
		return (-1, -1)
	r = pow(g, k, p) % q
	if r == 0:
		return (-1, -1)
	hashInt = int.from_bytes(SHA1(m), byteorder='big')
	s = (k_inv * (hashInt + x*r)) % q
	if s == 0:
		return (-1, -1)
	return (r, s)
	
# verify a message's private key and signature with its public key
def verifyDSA(m, r, s, y):
	if not ((0 < r) and (r < q) and (0 < s) and (s < q)):
		return False
	w = invmod(s, q)
	hashInt = int.from_bytes(SHA1(m), byteorder='big')
	u_1 = (hashInt * w) % q
	u_2 = (r * w) % q
	v = ((pow(g, u_1, p) * pow(y, u_2, p)) % p) % q
	return (v == r)
	
# with a known k value, recover private key from signature
def xFromK(m, k, r, s):
	hashInt = int.from_bytes(SHA1(m), byteorder='big')
	r_inv = invmod(r, q)
	return (((s * k) - hashInt) * r_inv) % q
		
# test that params are set up correctly
def testParams():
	N = q.bit_length()
	print("Value of N: " + str(N))
	L = p.bit_length()
	print("Value of L: " + str(L))
	if (p - 1) % q == 0:
		print("Success: p - 1 is a multiple of q")
	else:
		print("Warning: p was not correctly chosen")
	if pow(g, q, p) == 1:
		print("Success: q is the multiplicative order of g mod p")
	else:
		print("Warning: g was not correctly chosen")
		
# test signing and verification functions
def testSigning():
	print("Enter a message to sign:")
	msg = input()
	x, y = getKeys()
	r, s = signDSA(msg, x)
	if verifyDSA(msg, r, s, y):
		print("Signature verified!")
	else:
		print("Invalid signature.")
		
# test recovery of nonces from a known k
def testNonceRecovery():
	print("Enter a message to sign:")
	msg = input()
	x, y = getKeys()
	k = random.randint(0, q)
	r, s = signWithK(msg, x, k)
	testX = xFromK(msg, k, r, s)
	if testX == x:
		print("Nonce recovered!")
	else:
		print("Nonce not recovered.")
		
def doTests():
	testParams()
	testSigning()
	testNonceRecovery()
		
# recovers private key x from a broken implementation of DSA that only
# uses key values from 0 to 2^16
def recoverKey():
	y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
	secretMsg = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
	r = 548099063082341131477253921760299949438196259240
	s = 857042759984254168557880549501802188789837994940
	# bruteforce k values up to 2^16
	for k in range(0, 2**16):
		x = xFromK(secretMsg, k, r, s)
		testR, testS = signWithK(secretMsg, x, k)
		if (testR == r) and (testS == s):
			print("Nonce found: " + str(k))
			return x
	print("Nonce not found - private key could not be recovered.")
	
if __name__ == "__main__":
	# doTests()
	x = recoverKey()
	print("Private key: " + str(x))
	xStr = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big').hex()
	if hashlib.sha1(xStr.encode('utf-8')).hexdigest() == "0954edd5e0afe5542a4adf012611a91912a3ec16":
		print("Correct private key!")
	else:
		print("Incorrect private key.")