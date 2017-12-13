# solution to http://cryptopals.com/sets/3/challenges/23
# clone a MT19937 PRNG from its output

import time
from Challenge21 import MT19937

# undoes the right-shift and XOR tempering operation on a value in MT19937.
# returns untempered value (int)
def unShiftRightXOR(value, shift):
	result = 0
	# part length is equal to shift length - iterate through parts of value
	for i in range(0, 32, shift):
		# get part of value - use a bit mask of length shift
		partMask = ((2**shift - 1) << (32 - shift)) >> i
		part = value & partMask
		# xor the next part
		value ^= part >> shift
		# add part to result
		result |= part
	return result

# undoes the left-shift and XOR tempering operation on a value in MT19937.
# also takes a mask value to untemper the value
# returns untempered value (int)
def unShiftLeftXOR(value, shift, mask):
	result = 0
	# part length is equal to shift length - iterate through parts of value
	for i in range(0, 32, shift):
		# get part of value
		partMask = (0xFFFFFFFF >> (32 - shift)) << i
		part = partMask & value
		# xor the next part
		value ^= (part << shift) & mask
		# add part to result
		result |= part
	return result

# fully untempers a given value from MT19937 to get the untempered matrix value
# returns untempered value (int)
def untemper(value):
	result = value
	result = unShiftRightXOR(result, 18)
	result = unShiftLeftXOR(result, 15, 0xEFC60000)
	result = unShiftLeftXOR(result, 7, 0x9D2C5680)
	result = unShiftRightXOR(result, 11)
	return result

# gets 624 random numbers from initialPRNG (MT19937) and untempers each of them.
# these untempered values are spliced into another PRNG - the state of the PRNG is duplicated.
# returns newPRNG (MT19937)
def cloneMT19937(initialPRNG):
	newPRNG = MT19937(0)
	for i in range(0, 624):
		untempered = untemper(initialPRNG.extract_number())
		newPRNG.mt[i] = untempered
	return newPRNG

if __name__ == "__main__":
	currentTime = int(time.time())
	randomGen = MT19937(currentTime)
	clonedGen = cloneMT19937(randomGen)
	print("Cloned output: " + str(clonedGen.extract_number()))
	print("Actual output: " + str(randomGen.extract_number()))