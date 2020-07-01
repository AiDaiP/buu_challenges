from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Util.number import long_to_bytes,bytes_to_long


with open("flag_cipher","r") as f:
	c = f.read()
	f.close()

c = [c[i:i+32] for i in range(0, len(c), 32)]

for i in range(1, len(c)-1):
	cipher = AES.new(c[i], AES.MODE_ECB, "")
	print(cipher.decrypt(c[i+1]))