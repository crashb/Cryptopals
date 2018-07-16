# solution to http://cryptopals.com/sets/6/challenges/47
# Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

import RSAUtils
import random
from Crypto.Util import number
from math import ceil

k = 32
B = 2 ** (8 * (k - 2))

# generates a random sequence of bytes
def getRandomBytes(length):
	randomBytes = bytearray()
	for i in range(0, length):
		randomBytes.append(random.randint(0, 255))
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
	k = (n.bit_length() + 7) // 8  # get number of octets in n
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
	k = (n.bit_length() + 7) // 8  # get number of octets in n
	plainBytes = plainInt.to_bytes(k, 'big')
	return (plainBytes[0] == 0) and (plainBytes[1] == 2)
	
# step 2a - find s_1
def getS1(c_0, e, n, d):
	s = ceil(n / (3*B))
	while True:
		cTest = multiplyCipher(c_0, s, e, n)
		if checkPadding(cTest, d, n):
			# show that step 2a worked
			plainInt = pow(cTest, d, n)
			print(plainInt.to_bytes(k, 'big'))
			return s
		s += 1
	
# step 2c - find s_i for one interval
def getSi(M, c_0, s_0, e, n, d):
	a = M[0]
	b = M[1]
	
	s_i = s_0
	r_i = 2 * ceil((b*s_i - 2*B) / n)
	while True:
		s_i = ceil((2*B + r_i*n) / b)
		while s_i < (3*B + r_i*n) // a:
			cTest = multiplyCipher(c_0, s_i, e, n)
			if checkPadding(cTest, d, n):
				# test that step 2c is working
				plainInt = pow(cTest, d, n)
				print(plainInt.to_bytes(k, 'big'))
				return s_i
			s_i += 1
		r_i += 1
		
# step 3 - adjust boundaries based on s_i
def boundCalc(M, s_i, n):
	a = M[0]
	b = M[1]
	
	r_min = ceil((a*s_i - 3*B + 1) / n)
	r_max = (b*s_i - 2*B) // n
	print('r_min: ' + str(r_min))
	print('r_max: ' + str(r_max))
	
	r = r_min
	newLow = max(a, ceil((2*B + r*n) / s_i))
	
	r = r_max
	newHigh = min(b, (3*B - 1 + r*n) // s_i)
	
	return newLow, newHigh

if __name__ == "__main__":
	# set up problem - pad and encrypt message
	e, n, d = generateKey()
	msg = "kick it, CC"
	m_0 = makePadding(msg, e, n)
	c_0 = encrypt(m_0, e, n)
	
	s_1 = getS1(c_0, e, n, d)
	
	M = (2*B, 3*B - 1)
	print("Initial low bound:  " + str(M[0]))
	print("Initial high bound: " + str(M[1]))
	s_i = s_1
	M = boundCalc(M, s_i, n)
	print("Second low bound:  " + str(M[0]))
	print("Second high bound: " + str(M[1]))
	print("Difference:        " + str(M[1] - M[0]))
	while M[0] != M[1]:
		s_i = getSi(M, c_0, s_i, e, n, d)
		print("s_i: " + str(s_i))
		M = boundCalc(M, s_i, n)
		print("Low bound:  " + str(M[0]))
		print("High bound: " + str(M[1]))
		print("Difference: " + str(M[1] - M[0]))
	