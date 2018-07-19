# Cryptopals

These are my solutions to the original 6 sets of [Cryptopals crypto challenges](http://cryptopals.com) (also called the Matasano challenges).  These solutions are written in Python 3.


## [Set 1: Basics](http://cryptopals.com/sets/1)

  - [x] 01. Convert hex to base64
  - [x] 02. Fixed XOR
  - [x] 03. Single-byte XOR cipher
  - [x] 04. Detect single-character XOR
  - [x] 05. Implement repeating-key XOR
  - [x] 06. Break repeating-key XOR
  - [x] 07. AES in ECB mode
  - [x] 08. Detect AES in ECB mode

## [Set 2: Block Crypto](http://cryptopals.com/sets/2)

  - [x] 09. Implement PKCS#7 padding
  - [x] 10. Implement CBC mode
  - [x] 11. An ECB/CBC detection oracle
  - [x] 12. Byte-at-a-time ECB decryption (Simple)
  - [x] 13. ECB cut-and-paste
  - [x] 14. Byte-at-a-time ECB decryption (Harder)
  - [x] 15. PKCS#7 padding validation
  - [x] 16. CBC bitflipping attacks

## [Set 3: Block & Stream Crypto](http://cryptopals.com/sets/3)

  - [x] 17. The CBC padding oracle
  - [x] 18. Implement CTR, the stream cipher mode
  - [x] 19. Break fixed-nonce CTR mode using substitions
  - [x] 20. Break fixed-nonce CTR statistically
  - [x] 21. Implement the MT19937 Mersenne Twister RNG
  - [x] 22. Crack an MT19937 seed
  - [x] 23. Clone an MT19937 RNG from its output
  - [x] 24. Create the MT19937 stream cipher and break it

## [Set 4: Stream Crypto & Randomness](http://cryptopals.com/sets/4)

  - [x] 25. Break "random access read/write" AES CTR
  - [x] 26. CTR bitflipping
  - [x] 27. Recover the key from CBC with IV=Key
  - [x] 28. Implement a SHA-1 keyed MAC
  - [x] 29. Break a SHA-1 keyed MAC using length extension
  - [x] 30. Break an MD4 keyed MAC using length extension
  - [x] 31. Implement and break HMAC-SHA1 with an artificial timing leak
  - [x] 32. Break HMAC-SHA1 with a slightly less artificial timing leak

## [Set 5: Diffie-Hellman and Friends](http://cryptopals.com/sets/5)

  - [x] 33. Implement Diffie-Hellman
  - [x] 34. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
  - [x] 35. Implement DH with negotiated groups, and break with malicious "g" parameters
  - [x] 36. Implement Secure Remote Password (SRP)
  - [x] 37. Break SRP with a zero key
  - [x] 38. Offline dictionary attack on simplified SRP
  - [x] 39. Implement RSA
  - [x] 40. Implement an E=3 RSA Broadcast attack

## [Set 6: RSA and DSA](http://cryptopals.com/sets/6)

  - [x] 41. Implement unpadded message recovery oracle
  - [x] 42. Bleichenbacher's e=3 RSA Attack
  - [x] 43. DSA key recovery from nonce
  - [x] 44. DSA nonce recovery from repeated nonce
  - [x] 45. DSA parameter tampering
  - [x] 46. RSA parity oracle
  - [x] 47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
  - [x] 48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)]
  
# Still to come

* Refactoring of solutions to Sets 1-6
* Solutions to Sets 7 and 8 (beyond the "original" challenges)