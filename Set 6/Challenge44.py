# solution to http://cryptopals.com/sets/6/challenges/44
# DSA nonce recovery from repeated nonce

import random
import hashlib
import Challenge43

p = Challenge43.p
q = Challenge43.q
g = Challenge43.g

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

# parse messages, s, r, and m values from input file
def parseMessages():
	f = open("Challenge44Data.txt", "r")
	msgList = []
	mList = []
	rList = []
	sList = []
	for line in f.readlines():
		if line.find("msg: ") == 0:
			msgList.append(line[len("msg: "):-1]) # strip \n character
		if line.find("m: ") == 0:
			mList.append(int(line[len("m: "):-1], 16))
		if line.find("r: ") == 0:
			rList.append(int(line[len("r: "):-1]))
		if line.find("s: ") == 0:
			sList.append(int(line[len("s: "):-1]))
	return(msgList, mList, rList, sList)
	
# find two matching values in the rList
# if the r values are the same, they'll share a nonce
def findMatchingR(rList):
	for i in range(0, len(rList)):
		for j in range(i+1, len(rList)):
			if rList[i] == rList[j]:
				return (i, j)
	print("Could not find two messages that share a nonce!")
	return (-1, -1)

# get k value from m's and s's with re-used nonces
def getK(m1, m2, s1, s2):
	bottom = invmod((s1 - s2) % q, q)
	return (((m1 - m2) % q) * bottom) % q
	
if __name__ == "__main__":
	msgList, m, r, s = parseMessages()
	a, b = findMatchingR(r)
	k = getK(m[a], m[b], s[a], s[b])
	print("Shared nonce discovered: " + str(k))
	x = Challenge43.xFromK(msgList[a], k, r[a], s[a])
	print("Private key: " + str(x))
	xStr = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big').hex()
	if hashlib.sha1(xStr.encode('utf-8')).hexdigest() == "ca8f6f7c66fa362d40760d135b763eb8527d3d52":
		print("Correct private key!")
	else:
		print("Incorrect private key.")
	