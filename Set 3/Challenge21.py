# solution to http://cryptopals.com/sets/3/challenges/21
# implementation of Mersenne Twister MT19937 algorithm
# from https://en.wikipedia.org/w/index.php?title=Mersenne_Twister&oldid=809887122#Python_implementation

class MT19937:

	# Initialize the generator from a seed
	def __init__(self, seed):
		self.index = 624
		self.mt = [0] * 624
		self.mt[0] = seed # put the seed in the initial value
		for i in range(1, 624): # loop over each element
			 newVal = 1812433253 * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i
			 self.mt[i] = newVal & 0xFFFFFFFF # 32 least significant bits
	
	# extract a tempered value based on MT[index]
	# calling twist() every n = 624 numbers
	def extract_number(self):
		if self.index >= 624:
			if self.index > 624:
				raise ValueError("Generator was never seeded")
			self.twist()
			
		y = self.mt[self.index]
		y ^= (y >> 11)
		y ^= (y << 7) & 0x9D2C5680
		y ^= (y << 15) & 0xEFC60000
		y ^= (y >> 18)
		
		self.index += 1
		return y & 0xFFFFFFFF # return 32 least significant bits
	
	# Generate the next n values from the series x_i 
	def twist(self):
		for i in range(0, 624):
			x = (self.mt[i] & 0x80000000) + (self.mt[(i+1) % 624] & 0x7FFFFFFF)
			xA = x >> 1
			if x % 2 != 0:
				xA ^= 0x9908B0DF
			self.mt[i] = self.mt[(i+397) % 624] ^ xA
		self.index = 0
		 
if __name__ == "__main__":
	seed = 0
	rando = MT19937(seed)
	print("First PRNG number with seed " + str(seed) + ": " + str(rando.extract_number()))