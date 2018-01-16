# Python implementation of MD4 algorithm
# from https://gist.github.com/prokls/86b3c037df19a8c957fe

import binascii

def _pad(msg, prev_byte_length):
	n = len(msg)
	bit_len = (n + prev_byte_length) * 8
	index = n & 0x3f
	pad_len = 120 - index
	if index < 56:
		pad_len = 56 - index
	padding = b'\x80' + b'\x00' * 63
	suffix = bit_len.to_bytes(8, 'little', signed=False)
	padded_msg = msg + padding[:pad_len] + suffix
	return padded_msg

def _left_rotate(n, b):
	return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def _if(x, y, z):
	return x & y | ~x & z

def _maj(x, y, z):
	return x & y | x & z | y & z

def _xor3(x, y, z):
	return x ^ y ^ z

def _f1(a, b, c, d, k, s, X):
	return _left_rotate(a + _if(b, c, d) + X[k], s)

def _f2(a, b, c, d, k, s, X):
	return _left_rotate(a + _maj(b, c, d) + X[k] + 0x5a827999, s)

def _f3(a, b, c, d, k, s, X):
	return _left_rotate(a + _xor3(b, c, d) + X[k] + 0x6ed9eba1, s)


class MD4Hash(object):
	def __init__(self, A, B, C, D, byteLen):
		self.A = A
		self.B = B
		self.C = C
		self.D = D
		# Length in bytes of all data that has been processed so far
		self.prev_byte_length = byteLen

	def update(self, message_string):
		msg_bytes = _pad(message_string, self.prev_byte_length)
		for i in range(0, len(msg_bytes), 64):
			self._compress(msg_bytes[i:i+64])

	def _compress(self, block):
		a, b, c, d = self.A, self.B, self.C, self.D

		x = []
		for i in range(0, 64, 4):
			x.append(int.from_bytes(block[i:i+4], 'little', signed=False))

		a = _f1(a, b, c, d,  0,  3, x)
		d = _f1(d, a, b, c,  1,  7, x)
		c = _f1(c, d, a, b,  2, 11, x)
		b = _f1(b, c, d, a,  3, 19, x)
		a = _f1(a, b, c, d,  4,  3, x)
		d = _f1(d, a, b, c,  5,  7, x)
		c = _f1(c, d, a, b,  6, 11, x)
		b = _f1(b, c, d, a,  7, 19, x)
		a = _f1(a, b, c, d,  8,  3, x)
		d = _f1(d, a, b, c,  9,  7, x)
		c = _f1(c, d, a, b, 10, 11, x)
		b = _f1(b, c, d, a, 11, 19, x)
		a = _f1(a, b, c, d, 12,  3, x)
		d = _f1(d, a, b, c, 13,  7, x)
		c = _f1(c, d, a, b, 14, 11, x)
		b = _f1(b, c, d, a, 15, 19, x)

		a = _f2(a, b, c, d,  0,  3, x)
		d = _f2(d, a, b, c,  4,  5, x)
		c = _f2(c, d, a, b,  8,  9, x)
		b = _f2(b, c, d, a, 12, 13, x)
		a = _f2(a, b, c, d,  1,  3, x)
		d = _f2(d, a, b, c,  5,  5, x)
		c = _f2(c, d, a, b,  9,  9, x)
		b = _f2(b, c, d, a, 13, 13, x)
		a = _f2(a, b, c, d,  2,  3, x)
		d = _f2(d, a, b, c,  6,  5, x)
		c = _f2(c, d, a, b, 10,  9, x)
		b = _f2(b, c, d, a, 14, 13, x)
		a = _f2(a, b, c, d,  3,  3, x)
		d = _f2(d, a, b, c,  7,  5, x)
		c = _f2(c, d, a, b, 11,  9, x)
		b = _f2(b, c, d, a, 15, 13, x)

		a = _f3(a, b, c, d,  0,  3, x)
		d = _f3(d, a, b, c,  8,  9, x)
		c = _f3(c, d, a, b,  4, 11, x)
		b = _f3(b, c, d, a, 12, 15, x)
		a = _f3(a, b, c, d,  2,  3, x)
		d = _f3(d, a, b, c, 10,  9, x)
		c = _f3(c, d, a, b,  6, 11, x)
		b = _f3(b, c, d, a, 14, 15, x)
		a = _f3(a, b, c, d,  1,  3, x)
		d = _f3(d, a, b, c,  9,  9, x)
		c = _f3(c, d, a, b,  5, 11, x)
		b = _f3(b, c, d, a, 13, 15, x)
		a = _f3(a, b, c, d,  3,  3, x)
		d = _f3(d, a, b, c, 11,  9, x)
		c = _f3(c, d, a, b,  7, 11, x)
		b = _f3(b, c, d, a, 15, 15, x)

		# update state
		self.A = (self.A + a) & 0xffffffff
		self.B = (self.B + b) & 0xffffffff
		self.C = (self.C + c) & 0xffffffff
		self.D = (self.D + d) & 0xffffffff

	def digest(self):
		# print("A: " + str(self.A))
		# print("B: " + str(self.B))
		# print("C: " + str(self.C))
		# print("D: " + str(self.D))
		return binascii.hexlify(
			self.A.to_bytes(4, 'little', signed=False) + \
			self.B.to_bytes(4, 'little', signed=False) + \
			self.C.to_bytes(4, 'little', signed=False) + \
			self.D.to_bytes(4, 'little', signed=False)
		).decode('ascii')
		
def md4(data, a=0x67452301, b=0xEFCDAB89, c=0x98BADCFE, d=0x10325476, byteLen=0):
	"""MD4 Hashing Function

	A custom MD4 hashing function implemented entirely in Python.

	Arguments:
		data: A bytes or BytesIO object containing the input message to hash.

	Returns:
		A hex MD4 digest of the input message.
	"""
	md4obj = MD4Hash(a, b, c, d, byteLen)
	md4obj.update(data)
	return md4obj.digest()

if __name__ == '__main__':
	def check(msg, sig):
		print(md4(msg.encode('ascii')) == sig)

	check("", '31d6cfe0d16ae931b73c59d7e0c089c0')
	check("a", 'bde52cb31de33e46245e05fbdbd6fb24')
	check("abc", 'a448017aaf21d8525fc10ae87aa6729d')
	check("message digest", 'd9130a8164549fe818874806e1c7014b')
	check("abcdefghijklmnopqrstuvwxyz", 'd79e1c308aa5bbcdeea8ed63df412da9')
	check("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", '043f8582f241db351ce627e153e7f0e4')
	check("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 'e33b4ddc9c38f2199c3e7b164fcc0536')