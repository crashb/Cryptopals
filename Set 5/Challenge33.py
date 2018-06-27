# solution to http://cryptopals.com/sets/5/challenges/33
# implementation of Diffie-Hellman

import random
import hashlib

def GetPublicKey(p, g, a):
	return pow(g, a, p)
	
def GetSharedKeyVal(p, B, a):
	return pow(B, a, p)
	
def GetSharedKey(p, B, a):
	s = GetSharedKeyVal(p, B, a)
	return hashlib.sha1(str(s).encode('utf-8')).hexdigest()

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
	
if __name__ == "__main__":
	a = random.randint(0, p - 1)
	A = GetPublicKey(p, g, a)
	b = random.randint(0, p - 1)
	B = GetPublicKey(p, g, b)

	key1 = GetSharedKey(p, B, a)
	print("Key 1: " + key1)
	key2 = GetSharedKey(p, A, b)
	print("Key 2: " + key2)
	
	if key1 == key2:
		print("Test succeeded!")
	else:
		print("Test failed.")