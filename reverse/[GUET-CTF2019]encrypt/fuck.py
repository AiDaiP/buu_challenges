'''enc = 'Z`TzzTrD|fQP[_VVL|yneURyUmFklVJgLasJroZpHRxIUlH\\vZE='
print(len(enc))
print(len(enc)%3)#1
fuck = ''
for i in range(3,len(enc),4):
	print(i)
	flag = False
	for j in range(0xff+1):
		for k in range(0xff+1):
			for l in range(0xff+1):
				if ord(enc[i-3]) == ((j >> 2) & 0x3F) + 61 and \
				ord(enc[i-2]) == ((((k & 0xFF) >> 4) | 16 * j) & 0x3F) + 61 and \
				 ord(enc[i-1]) == ((((l & 0xFF) >> 6) | 4 * k) & 0x3F) + 61 and \
				 ord(enc[i]) == (l & 0x3F) + 61:
					print(hex(j),hex(k),hex(l))
					fuck = fuck + chr(j)+chr(k)+chr(l)
	print(fuck.encode('hex'))
#7635fdf57d47fe95137a26593fff31a1857c63026ebd936a3e4d8dd727732d5ecc62f2dfe5d2

'''

fuck =  [0x0,0x0,0xb0,0x31,0x75,0x70,0xf8,0xdf,0x07,0x3c,0x78,0x71,
0x50,0x29,0x2c,0x16,0x69,0x12,0xc8,0x2b,0x3b,0x7f,0xb2,0xe7,
0x4b,0x68,0x8c,0xc5,0xa6,0x15,0x03,0x58,0x47,0x04,0x13,0x8d,
0x87,0x26,0x09,0xed,0x17,0x8a,0xc2,0xf2,0x43,0xc0,0xac,0x59,
0x97,0xf5,0x3f,0x67,0x5e,0x39,0x86,0xd5,0x72,0x61,0xda,0xf7,
0x01,0x05,0x8b,0xc3,0xb1,0x77,0xaf,0x1d,0x30,0xc6,0x45,0x0e,
0x5f,0xee,0xae,0xf0,0x28,0xce,0xcd,0xa7,0x9b,0x2a,0x19,0x48,
0x08,0x44,0x20,0xfe,0x6d,0xb5,0x2e,0x6a,0xf1,0x34,0xbc,0x1e,
0x3e,0xcc,0x41,0x92,0xd8,0xbd,0xa5,0xe8,0x4d,0x0a,0x49,0x0d,
0xa2,0xfa,0x62,0x74,0xd4,0x83,0x96,0x94,0x3d,0xcb,0x18,0x63,
0x99,0x46,0xca,0xb7,0x8e,0xcf,0xfb,0xa3,0x6c,0x7e,0x51,0x27,
0x60,0x9a,0x11,0xf3,0x5c,0x6e,0xba,0x42,0x76,0x2f,0xef,0xbf,
0x21,0xaa,0xe4,0xd6,0x1b,0x55,0x7d,0xbe,0xea,0xd3,0x10,0xf4,
0xc7,0x4a,0x23,0x79,0x84,0xa4,0x1c,0xab,0x14,0xdb,0x4c,0x3a,
0xb8,0x52,0xec,0x37,0x38,0xb6,0xd2,0xa0,0x5a,0x5b,0x98,0x66,
0x54,0x9e,0x4e,0x4f,0xb4,0xc4,0xc9,0xd0,0x25,0x9c,0x80,0xde,
0x2d,0x06,0x22,0x0b,0x91,0x6b,0x9f,0xf6,0xe6,0xe2,0xc1,0x0f,
0x93,0x90,0x7b,0x9d,0x8f,0xdd,0xe5,0x65,0x35,0xad,0xa9,0xdc,
0x82,0xbb,0x00,0x53,0xd1,0xa8,0x33,0xe9,0x40,0x1a,0xff,0xa1,
0x95,0x36,0xd9,0xeb,0x89,0xe3,0x7c,0x73,0x85,0x88,0x7a,0xe0,
0xfd,0x64,0x0c,0x57,0x32,0xb3,0xb9,0x1f,0xd7,0xfc,0x81,0xe1,
0x02,0xf9,0x5d,0x56,0x6f,0x24]

v7 = fuck[0]
v8 = fuck[1]

enc = '7635fdf57d47fe95137a26593fff31a1857c63026ebd936a3e4d8dd727732d5ecc62f2dfe5d2'.decode('hex')
flag = ''
for i in range(len(enc)):
	v7 = (v7+1)&0xff
	v3 = fuck[v7+2]
	v8 = (v8+v3)&0xff
	v4 = fuck[2+v8]
	fuck[2+v7] = v4
	fuck[2+v8] = v3
	key = fuck[2+((v3+v4)&0xff)]
	for j in range(0xff+1):
		if j ^ key == ord(enc[i]):
			flag += chr(j)
print(flag)