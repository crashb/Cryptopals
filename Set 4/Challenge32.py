# solution to http://cryptopals.com/sets/4/challenges/32
# break HMAC-SHA1 with a less artificial timing leak
# main difference is that response time is averaged over 
# several connections to provide higher precision

# NOTE: turn wi-fi off on your computer to reduce network delays.
#       if you're experiencing problems, iterate through the bytes more.

import time
import binascii
import urllib.request

# measures the response time to visit a particular URL (string argument).
# outputs a float, the number of seconds it took to read the URL.
def get_response_time(url):
	start = time.time()
	f = urllib.request.urlopen(url)
	page = f.read()
	end = time.time()
	f.close()
	return (end - start)
	
# to bruteforce a single byte of the MAC, send all possible requests to
# the server. a correct byte is most likely to result in a longer response
# time.  returns url string with the most likely byte appended.
def bruteforce_byte(url):
	urlPrefix = url
	times = {}
	avg_times = {}
	
	for i in range(256):
		times[i] = []
	# run through all possible bytes several times
	for i in range(256 * 20):
		testByte = bytes([i % 256]).hex()
		testURL = urlPrefix + testByte
		response_time = get_response_time(testURL)
		print(testURL + " response time: {0:.{1}}s".format(response_time, 5))
		times[i % 256].append(response_time)
	for i in range(256):
		avg_times[i] = sum(times[i])/len(times[i])
	
	correctNum = max(avg_times, key=avg_times.get)
	correctByte = bytes([correctNum]).hex()
	print("Byte cracked: " + correctByte + " with avg response time {0:.{1}}s".format(avg_times[correctNum], 5))
	return correctByte
	
# bruteforces the HMAC for a string input.
# returns the HMAC hex string.
def bruteforce_hmac(input):
	urlPrefix = "http://127.0.0.1:8080/test?file=" + targetInput + "&signature="
	hmac = ''
	for i in range(20):
		url = urlPrefix + hmac
		newByte = bruteforce_byte(url)
		hmac += newByte
	return hmac
	
if __name__ == "__main__":
	print("Enter a string you would like to learn the MAC for:")
	targetInput = input();
	hmac = bruteforce_hmac(targetInput)
	print("HMAC discovered for " + targetInput + ": " + hmac)