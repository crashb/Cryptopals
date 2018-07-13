# solution to http://cryptopals.com/sets/5/challenges/40
# Implement an E=3 RSA Broadcast attack

import Challenge39
from decimal import *

if __name__ == "__main__":
	# needs to be high enough precision to calculate cube root
	getcontext().prec = 100
	secret = "yellow submarine"
	
	e1, n1, d1 = Challenge39.generateKey()
	e2, n2, d2 = Challenge39.generateKey()
	e3, n3, d3 = Challenge39.generateKey()
	
	c1 = Challenge39.encrypt(secret, e1, n1)
	c2 = Challenge39.encrypt(secret, e2, n2)
	c3 = Challenge39.encrypt(secret, e3, n3)
	
	ms1 = n2 * n3
	ms2 = n1 * n3
	ms3 = n1 * n2
	n123 = n1 * n2 * n3
	
	rawResult = ((c1 * ms1 * Challenge39.invmod(ms1, n1)) +
				(c2 * ms2 * Challenge39.invmod(ms2, n2)) +
				(c3 * ms3 * Challenge39.invmod(ms3, n3))) % n123
	decResult = Decimal(rawResult) ** (Decimal(1) / Decimal(3))
	result = int(decResult.quantize(Decimal('1.'), rounding=ROUND_UP))
				
	plainText = result.to_bytes((result.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
	print("Decoded string: " + plainText)