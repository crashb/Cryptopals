# solution to http://cryptopals.com/sets/6/challenges/42
# Bleichenbacher's e=3 RSA Attack

import RSAUtils
import time
import hashlib
from decimal import *

e = 3
blockLength = 1024

# asn.1 code from https://github.com/sybrenstuvel/python-rsa/blob/master/rsa/pkcs1.py
ASN1_MD5 = b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'

# needs to be high enough precision to calculate cube root
getcontext().prec = 1024

# calculate MD5 hex digest for a given string
def MD5(s):
	return hashlib.md5(s.encode('utf-8')).hexdigest()

# calculate cube root with a high degree of precision (round up)
def cubeRoot(x):	
	decResult = Decimal(x) ** (Decimal(1) / Decimal(3))
	return int(decResult.quantize(Decimal('1.'), rounding=ROUND_UP))
	
# faulty implementation of verifying RSA signature - does not check
# for all padding to be present
def verifySig(msg, encSig):
	# decrypt signature
	sigInt = encSig ** e
	sig = sigInt.to_bytes(blockLength // 8, byteorder='big')
	if len(sig) != blockLength // 8:
		print("Signature is wrong length")
		return False
	if sig.find(b'\x00\x01\xff') != 0:
		print("Signature does not start with proper padding")
		return False
	# extract and verify hash from signature
	hashStart = sig.find(b'\x00' + ASN1_MD5) + len(b'\x00' + ASN1_MD5)
	hash = sig[hashStart:hashStart + 16]
	if hash == bytes.fromhex(MD5(msg)):
		return True
	else:
		print("Signature contains invalid hash")
		return False
		
# forge a signature for a given message. RSA signatures are ciphertext,
# so this function just returns an integer that, when cubed, yields
# the RSA signature that the faulty implementation will accept
def forgeSig(msg):
	msgHash = bytes.fromhex(MD5(msg))
	payload = b'\x00' + ASN1_MD5 + msgHash
	garbageSig = b'\x00\x01\xff' + payload
	garbageSig = garbageSig + b'\x00' * (blockLength // 8 - len(garbageSig))
	# calculate functional cube number
	garbageSigInt = int.from_bytes(garbageSig, byteorder='big')
	return cubeRoot(garbageSigInt)
	
if __name__ == "__main__":
	# we don't even need to generate an RSA key, since the modulus is not used
	msg = 'hi mom'
	forged = forgeSig(msg)
	if verifySig(msg, forged):
		print("Valid signature provided for message '" + msg + "'")
	else:
		print("Invalid signature!")