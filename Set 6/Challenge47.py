# solution to http://cryptopals.com/sets/6/challenges/47
# Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

import RSAUtils
import random
from Crypto.Util import number

k = 32
B = 2 ** (8 * (k - 2))

# i had to write my own ceil function - math.ceil() was not behaving
def ceil(a, b):
	if a % b == 0:
		return a // b
	else:
		return a // b + 1

# generates a random sequence of bytes
def getRandomBytes(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(1, 255)) # not 0
	return randomBytes

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	g, y, x = egcd(b%a,a)
	return (g, x - (b//a) * y, y)

def invmod(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('No modular inverse')
	return x % m
	
# return a random prime number
def getPrime():
	return number.getPrime(128)
	
def checkRelativelyPrime(a, b):
	g = egcd(a, b)[0]
	if g == 1:
		return True
	else:
		return False
		
def generateKey():
	e = 3
	et = e
	while not checkRelativelyPrime(e, et):
		p = getPrime()
		q = getPrime()
		et = (p - 1) * (q - 1)
	n = p * q
	d = invmod(e, et)
	return (e, n, d)
	
# pads a plaintext message to an int
def makePadding(msg, e, n):
	msgBytes = msg.encode('utf-8')
	ps = getRandomBytes(k - 3 - len(msgBytes))
	eb = b'\x00\x02' + ps + b'\x00' + msgBytes
	return int.from_bytes(eb, 'big')
	
# encrypts a plaintext int to a ciphertext int
def encrypt(m, e, n):
	return pow(m, e, n)

# multiply an RSA ciphertext c so that plaintext changes by factor s
def multiplyCipher(c, s, e, n):
	return (c * pow(s, e, n)) % n

# decrypts RSA and determines if padding is valid
def checkPadding(cipherInt, d, n):
	plainInt = pow(cipherInt, d, n)
	plainBytes = plainInt.to_bytes(k, 'big')
	return (plainBytes[0] == 0) and (plainBytes[1] == 2)
	
# searches for s_1 > n/(3*B) such that multiplication is PKCS conformant
def step2a(c, e, n, d):
	s_1 = ceil(n, 3*B)
	while True:
		cTest = multiplyCipher(c, s_1, e, n)
		if checkPadding(cTest, d, n):
			return s_1
		s_1 += 1
		
# calculate s_i in a fast way so as to halve the distance
def step2c(c, lastS, M, e, n, d):
	a, b = M
	r_i = ceil(2 * (b*lastS - 2*B), n)
	while True:
		s_min = ceil((2*B + r_i*n), b)
		s_max = ceil((3*B + r_i*n), a)
		for s_i in range(s_min, s_max):
			cTest = multiplyCipher(c, s_i, e, n)
			if checkPadding(cTest, d, n):
				return s_i
		r_i += 1
		
# narrow the set of solutions
def step3(lastM, s_i, n):	
	a, b = lastM
	r_min = ceil((a*s_i - 3*B + 1), n)
	r_max = ceil((b*s_i - 2*B), n)
	
	for r in range(r_min, r_max + 1):
		newA = max(a, ceil((2*B + r*n), s_i))
		newB = min(b, (3*B - 1 + r*n) // s_i)
		if newA <= newB:
			return (newA, newB)

if __name__ == "__main__":
	secret = "kick it, CC"
	e, n, d = generateKey()
	padded = makePadding(secret, e, n)
	c_0 = encrypt(padded, e, n)
	M = (2*B, 3*B - 1)
	i = 1
	
	# step 2
	while not (M[0] == M[1]):
		if i == 1:
			# print("Doing step 2a...")
			s_i = step2a(c_0, e, n, d)
		else:
			# print("Doing step 2c...")
			s_i = step2c(c_0, s_i, M, e, n, d)
		# print("Doing step 3...")
		M = step3(M, s_i, n)
		i += 1
		
	print("Decoded message:")
	solution = M[0].to_bytes(k, 'big')
	print(solution)