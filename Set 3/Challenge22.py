# solution to http://cryptopals.com/sets/3/challenges/22
# crack an MT19937 seed given the approximate time it was seeded

import time
import random
from Challenge21 import MT19937

# waits 40-1000 seconds, gets a random number, waits 40-1000 seconds, returns the number (int)
def getRandomNumber():
	print("Getting random number...")
	time.sleep(40 + random.randint(0, 960))
	currentTime = int(time.time())
	randomGen = MT19937(currentTime)
	randomNum = randomGen.extract_number()
	time.sleep(40 + random.randint(0, 960))
	return randomNum
	
# given a randomly generated number, return timestamp used to generate it (int)
def findRandomSeed(randomInput):
	currentTime = int(time.time())
	for i in range(0, 3600):
		newSeed = currentTime - i
		randomGen = MT19937(newSeed)
		randomNum = randomGen.extract_number()
		if randomNum == randomInput:
			return newSeed

if __name__ == "__main__":
	randNo = getRandomNumber()
	print("Random number: " + str(randNo))
	print("Current time: " + str(int(time.time())))
	randSeed = findRandomSeed(randNo)
	print("Discovered seed: " + str(randSeed))