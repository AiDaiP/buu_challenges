flag = ''
key = [0x52,0xFD,0x16,0xA4,0x89,0xBD,0x92,0x80,0x13,0x41,0x54,0xA0,0x8D,0x45,0x18,0x81,0xDE,0xFC,0x95,0xF0,0x16,0x79,0x1A,0x15,0x5B,0x75,0x1F]
for i in range(5,32):
	for j in range(0xff):
		a = (j^((32-i)))
		if i%2:
			res = (a>>2)|((a<<6)%0xff)
		else:
			res = ((a<<2)%0xff)|(a>>6)
		if res == key[i-5]:
			flag += chr(j)
print(flag)