# solution to http://cryptopals.com/sets/5/challenges/39
# Implement RSA

from Crypto.Util import number
import random
import sys
sys.setrecursionlimit(1000000)

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
	
def encrypt(plainStr, e, n):
	plainInt = int.from_bytes(plainStr.encode('utf-8'), byteorder='big', signed=False)
	return pow(plainInt, e, n)
	
def decrypt(cipherInt, d, n):
	decodeInt = pow(cipherInt, d, n)
	return decodeInt.to_bytes((decodeInt.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
	
if __name__ == "__main__":

	print("Generating RSA key...")
	# ensure relative primality
	e = 3
	et = e
	while not checkRelativelyPrime(e, et):
		p = getPrime()
		q = getPrime()
		et = (p - 1) * (q - 1)
	n = p * q
	d = invmod(e, et)
	print("Generated!")
	
	print("Enter a string to encrypt:")
	plainStr = input()
	cipherInt = encrypt(plainStr, e, n)
	print("Encrypted integer: " + str(cipherInt))
	decodeStr = decrypt(cipherInt, d, n)
	print("Decrypted string: " + decodeStr)