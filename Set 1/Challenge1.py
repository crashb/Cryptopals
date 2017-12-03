# solution to http://cryptopals.com/sets/1/challenges/1
# hex string to base64

import base64

def hexStringToBase64(hexString):
	hexBytes = bytearray.fromhex(hexString)
	base64Bytes = base64.b64encode(hexBytes)
	base64String = base64Bytes.decode("ascii")
	return base64String
	
if __name__ == "__main__":
	hexString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	base64String = hexStringToBase64(hexString)
	print("Input:  " + hexString)
	print("Output: " + base64String)