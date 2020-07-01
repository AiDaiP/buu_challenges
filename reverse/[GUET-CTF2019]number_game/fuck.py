from pwn import *

i = 0
while True:
	r = process('./number_game')
	r.sendline(str(i))
	fuck = r.recvline()
	if 'TQL' in fuck:
		print(i)
		break
	i += 1
	r.close()