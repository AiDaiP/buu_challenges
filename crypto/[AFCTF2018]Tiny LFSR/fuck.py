f1 = open('cipher.txt','r')
f2 = open('Plain.txt','r')

c = f1.read()
p = f2.read()

key = ''
for i in range(len(c)):
	key+=chr(ord(c[i])^ord(p[i]))

key = key.encode('hex')
R = int(key,16)


flag = open('flag_encode.txt','r')
s = flag.read()
def lfsr(R, mask):
	output = (R << 1) & 0xffffffffffffffff
	i=(R&mask)&0xffffffffffffffff
	lastbit=0
	while i!=0:
		lastbit^=(i&1)
		i=i>>1
	output^=lastbit
	return (output,lastbit)

mask = 0b1101100000000000000000000000000000000000000000000000000000000000

a = ''.join([chr(int(b, 16)) for b in [key[i:i+2] for i in range(0, len(key), 2)]])
print(a)
lent = len(s)
ff = open('fuck','w')
for i in range(0, len(a)):
	ff.write(chr(ord(s[i])^ord(a[i])))

for i in range(len(a), lent):
    tmp=0
    for j in range(8):
        (R,out)=lfsr(R,mask)
        tmp=(tmp << 1)^out
    ff.write(chr(tmp^ord(s[i])))