# solution to http://cryptopals.com/sets/4/challenges/31
# break HMAC-SHA1 with an artificial timing leak

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
	for i in range(256):
		testByte = bytes([i]).hex()
		testURL = urlPrefix + testByte
		times[testByte] = get_response_time(testURL)
	correctByte = max(times, key=times.get)
	print("Byte cracked: " + correctByte + " with response time " + str(times[correctByte]))
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